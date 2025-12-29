#!/usr/bin/env python3
"""Unlock Anki conjugation cards based on maturity ladder rules."""

import argparse
import json
import logging
import os
import random
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


class AnkiConnectError(Exception):
    pass


class AnkiConnectClient:
    def __init__(self, url, version, timeout=10):
        self.url = url
        self.version = version
        self.timeout = timeout

    def request(self, action, params=None):
        payload = {"action": action, "version": self.version}
        if params is not None:
            payload["params"] = params
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read().decode("utf-8")
        except (urllib.error.URLError, TimeoutError) as exc:
            raise AnkiConnectError(str(exc)) from exc

        try:
            decoded = json.loads(body)
        except json.JSONDecodeError as exc:
            raise AnkiConnectError(f"Invalid JSON response: {body}") from exc

        if decoded.get("error") is not None:
            raise AnkiConnectError(decoded["error"])
        return decoded.get("result")


class AnkiProcessManager:
    def __init__(self, launch_cfg, logger):
        self.launch_cfg = launch_cfg
        self.logger = logger
        self.process = None

    def _list_processes(self):
        try:
            output = subprocess.check_output(
                ["ps", "-eo", "pid=,comm=,args="], text=True
            )
        except subprocess.SubprocessError:
            return []

        processes = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(None, 2)
            if len(parts) == 2:
                pid_str, comm = parts
                args = ""
            else:
                pid_str, comm, args = parts
            try:
                pid = int(pid_str)
            except ValueError:
                continue
            processes.append({"pid": pid, "comm": comm, "args": args})
        return processes

    def is_anki_running(self):
        match_tokens = self.launch_cfg.get("process_match", [])
        if not match_tokens:
            return False
        current_pid = os.getpid()
        for proc in self._list_processes():
            if proc["pid"] == current_pid:
                continue
            haystack = f"{proc['comm']} {proc['args']}".lower()
            if any(token.lower() in haystack for token in match_tokens):
                return True
        return False

    def shutdown_existing(self, client=None):
        match_tokens = self.launch_cfg.get("shutdown_match") or self.launch_cfg.get(
            "process_match", []
        )
        if not match_tokens:
            return

        if client is not None:
            self.logger.info("Skipping guiExitAnki; using SIGINT for sync-on-exit")

        current_pid = os.getpid()
        targets = []
        for proc in self._list_processes():
            if proc["pid"] == current_pid:
                continue
            haystack = f"{proc['comm']} {proc['args']}".lower()
            if any(token.lower() in haystack for token in match_tokens):
                targets.append(proc["pid"])

        if not targets:
            return

        self.logger.info("Shutting down existing Anki processes: %s", targets)
        grace = self.launch_cfg.get("sync_grace_seconds", 5)
        self._terminate_pids(targets, match_tokens, grace_seconds=grace)
        return

    def _terminate_pids(self, targets, match_tokens, grace_seconds=5):
        match_lower = [token.lower() for token in match_tokens]
        filtered = []
        for proc in self._list_processes():
            haystack = f"{proc['comm']} {proc['args']}".lower()
            if any(token in haystack for token in match_lower):
                if targets is None or proc["pid"] in targets:
                    filtered.append(proc["pid"])
        if not filtered:
            return

        # SIGINT first to mimic Ctrl-C (triggers sync on exit).
        for pid in filtered:
            try:
                os.kill(pid, signal.SIGINT)
            except OSError:
                continue

        grace_deadline = time.time() + grace_seconds
        while time.time() < grace_deadline:
            remaining = []
            for pid in filtered:
                try:
                    os.kill(pid, 0)
                    remaining.append(pid)
                except OSError:
                    continue
            if not remaining:
                return
            time.sleep(0.5)

        timeout = self.launch_cfg.get("shutdown_timeout_seconds", 20)
        deadline = time.time() + timeout
        while time.time() < deadline:
            remaining = []
            for pid in filtered:
                try:
                    os.kill(pid, 0)
                    remaining.append(pid)
                except OSError:
                    continue
            if not remaining:
                return
            time.sleep(0.5)

        for pid in filtered:
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                continue

        deadline = time.time() + timeout
        while time.time() < deadline:
            remaining = []
            for pid in filtered:
                try:
                    os.kill(pid, 0)
                    remaining.append(pid)
                except OSError:
                    continue
            if not remaining:
                return
            time.sleep(0.5)

        for pid in filtered:
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                continue

        # Final sweep to ensure no matching processes remain.
        survivors = []
        for proc in self._list_processes():
            haystack = f"{proc['comm']} {proc['args']}".lower()
            if any(token in haystack for token in match_lower):
                survivors.append(proc["pid"])
        if survivors:
            self.logger.warning("Anki processes still running after kill: %s", survivors)

    def maybe_launch(self, client=None):
        if not self.launch_cfg.get("enabled", False):
            self.logger.info("Anki launch disabled; assuming it is already running")
            return False
        if self.is_anki_running():
            if self.launch_cfg.get("restart_if_running", True):
                self.logger.info("Anki running; restarting for fresh sync")
                self.shutdown_existing(client=client)
            else:
                self.logger.info("Anki already running; no launch needed")
                return False
        command = self.launch_cfg.get("command")
        if not command:
            raise RuntimeError("launch.enabled is true but launch.command is empty")
        self.logger.info("Launching Anki: %s", " ".join(command))
        self.process = subprocess.Popen(command, start_new_session=True)
        return True

    def shutdown(self, client=None):
        if not self.process:
            return
        if client is not None:
            self.logger.info("Skipping guiExitAnki; using SIGINT for sync-on-exit")

        timeout = self.launch_cfg.get("shutdown_timeout_seconds", 20)
        grace = self.launch_cfg.get("sync_grace_seconds", 5)
        try:
            self.process.wait(timeout=timeout)
            self.logger.info("Anki process exited")
            return
        except subprocess.TimeoutExpired:
            self.logger.warning("Anki did not exit; sending SIGINT for sync")
            try:
                os.killpg(os.getpgid(self.process.pid), signal.SIGINT)
            except OSError:
                pass
            deadline = time.time() + grace
            while time.time() < deadline:
                if self.process.poll() is not None:
                    self.logger.info("Anki process exited after SIGINT")
                    return
                time.sleep(0.5)
            self.logger.warning("Anki still running after SIGINT; forcing shutdown")

        match_tokens = self.launch_cfg.get("shutdown_match") or self.launch_cfg.get(
            "process_match", []
        )
        if match_tokens:
            self._terminate_pids(None, match_tokens, grace_seconds=grace)
        else:
            self.process.terminate()
            try:
                self.process.wait(timeout=timeout)
                self.logger.info("Anki process exited after SIGTERM")
                return
            except subprocess.TimeoutExpired:
                self.logger.warning("Anki did not exit; sending SIGKILL")
            self.process.kill()
            self.process.wait()


def load_config(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def setup_logging(cfg):
    level_name = cfg.get("logging", {}).get("level", "INFO")
    level = getattr(logging, level_name.upper(), logging.INFO)
    logger = logging.getLogger("anki-conjugation")
    logger.setLevel(level)
    logger.handlers.clear()

    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    log_path = cfg.get("logging", {}).get("log_path")

    if log_path:
        file_handler = logging.FileHandler(log_path)
        file_handler.setFormatter(formatter)
        file_handler.setLevel(level)
        logger.addHandler(file_handler)

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    stream_handler.setLevel(level)
    logger.addHandler(stream_handler)

    return logger


def wait_for_anki(client, max_wait, interval, logger):
    start = time.time()
    while True:
        try:
            client.request("version")
            logger.info("AnkiConnect ready")
            return True
        except AnkiConnectError as exc:
            if time.time() - start > max_wait:
                logger.error("AnkiConnect not reachable after %.1fs: %s", max_wait, exc)
                return False
            time.sleep(interval)


def sync_collection(client, cfg, logger, phase="before"):
    if phase == "after" and not cfg.get("sync_after_run", True):
        logger.info("Post-run sync skipped by configuration")
        return True
    if phase == "before" and not cfg.get("sync_before_run", True):
        logger.info("Sync skipped by configuration")
        return True
    try:
        client.request("sync")
        logger.info("Sync completed (%s)", phase)
        return True
    except AnkiConnectError as exc:
        msg = str(exc)
        logger.warning("Sync failed (%s): %s", phase, msg)
        required_key = "sync_required" if phase == "before" else "sync_after_required"
        if cfg.get(required_key, False):
            return False
        if "unknown action" in msg.lower() or "not supported" in msg.lower():
            logger.warning("Proceeding without sync; AnkiConnect sync unsupported")
            return True
        return False


def safe_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def batched(items, size):
    if size <= 0:
        raise ValueError("batch size must be positive")
    for idx in range(0, len(items), size):
        yield items[idx : idx + size]


def card_interval(info):
    return safe_int(info.get("interval", info.get("ivl")), default=0)


def card_note_id(info):
    return safe_int(info.get("nid", info.get("note")), default=None)


def card_is_suspended(info):
    if info.get("suspended") is True:
        return True
    return safe_int(info.get("queue"), default=0) == -1


def unlock_conjugations(client, cfg, logger, dry_run=False):
    target_deck = cfg["target_deck"]
    target_model = cfg["target_model"]
    base_ord = cfg["base_card_ord"]
    conj_ords = set(cfg["conjugation_card_ords"])
    threshold = cfg.get("maturity_threshold_days", 30)

    if cfg.get("random_seed") is not None:
        random.seed(cfg["random_seed"])
    debug_stats = cfg.get("debug_stats", False)
    batch_size = cfg.get("cards_info_batch_size", 200)

    query = f'deck:"{target_deck}" note:"{target_model}" prop:ivl>={threshold}'
    base_card_ids = client.request("findCards", {"query": query})
    if debug_stats:
        logger.info("Base query: %s -> %s cards", query, len(base_card_ids))
    if not base_card_ids:
        if debug_stats:
            deck_count = client.request(
                "findCards", {"query": f'deck:"{target_deck}"'}
            )
            model_count = client.request(
                "findCards", {"query": f'note:"{target_model}"'}
            )
            deck_model_count = client.request(
                "findCards",
                {"query": f'deck:"{target_deck}" note:"{target_model}"'},
            )
            logger.info(
                "Diagnostics deck=%s model=%s deck+model=%s",
                len(deck_count),
                len(model_count),
                len(deck_model_count),
            )
        return {"notes": 0, "unlocked": 0, "details": []}

    base_infos = []
    for chunk in batched(base_card_ids, batch_size):
        base_infos.extend(client.request("cardsInfo", {"cards": chunk}))
    note_ids = set()
    base_candidates = []
    for info in base_infos:
        if info.get("ord") == base_ord and card_interval(info) >= threshold:
            nid = card_note_id(info)
            if nid is None or nid <= 0:
                continue
            base_candidates.append(nid)
            note_ids.add(nid)
    if debug_stats:
        logger.info("Base ord=%s eligible cards=%s", base_ord, len(base_candidates))
        if not base_candidates:
            ord_counts = {}
            for info in base_infos:
                ord_counts[info.get("ord")] = ord_counts.get(info.get("ord"), 0) + 1
            logger.info("Ord counts in base query: %s", ord_counts)
            ord_ivls = [
                safe_int(info.get("interval", info.get("ivl")), default=None)
                for info in base_infos
                if info.get("ord") == base_ord
            ]
            ord_ivls = [ivl for ivl in ord_ivls if ivl is not None]
            if ord_ivls:
                logger.info(
                    "Base ord interval stats: count=%s min=%s max=%s",
                    len(ord_ivls),
                    min(ord_ivls),
                    max(ord_ivls),
                )
                ge_count = sum(1 for ivl in ord_ivls if ivl >= threshold)
                logger.info("Base ord interval >= %s: %s", threshold, ge_count)
            else:
                logger.info("Base ord interval stats: no values found")
                if base_infos:
                    logger.info(
                        "cardsInfo keys sample: %s", sorted(base_infos[0].keys())
                    )

    unlocked = []
    limit_notes = cfg.get("debug_limit_notes")
    note_id_list = sorted(note_ids)
    if limit_notes:
        note_id_list = note_id_list[: int(limit_notes)]
    evaluated_count = len(note_id_list)

    cards_by_nid = {}
    if limit_notes:
        for nid in note_id_list:
            card_ids = client.request("findCards", {"query": f"nid:{nid}"})
            if not card_ids:
                continue
            infos = []
            for chunk in batched(card_ids, batch_size):
                infos.extend(client.request("cardsInfo", {"cards": chunk}))
            cards_by_nid[nid] = infos
    else:
        all_card_ids = client.request(
            "findCards", {"query": f'deck:"{target_deck}" note:"{target_model}"'}
        )
        if debug_stats:
            logger.info("Deck+model query -> %s cards", len(all_card_ids))
        all_infos = []
        for chunk in batched(all_card_ids, batch_size):
            all_infos.extend(client.request("cardsInfo", {"cards": chunk}))
        for info in all_infos:
            nid = card_note_id(info)
            if nid is None or nid <= 0:
                continue
            cards_by_nid.setdefault(nid, []).append(info)

    if debug_stats:
        ord_counts = {}
        ord_suspended = {}
        for infos in cards_by_nid.values():
            for info in infos:
                ord_val = info.get("ord")
                ord_counts[ord_val] = ord_counts.get(ord_val, 0) + 1
                if card_is_suspended(info):
                    ord_suspended[ord_val] = ord_suspended.get(ord_val, 0) + 1
        logger.info("Ord counts (evaluated notes): %s", ord_counts)
        logger.info("Ord suspended counts (evaluated notes): %s", ord_suspended)
        suspended_in_deck = client.request(
            "findCards", {"query": f'deck:"{target_deck}" is:suspended'}
        )
        suspended_in_model = client.request(
            "findCards", {"query": f'note:"{target_model}" is:suspended'}
        )
        suspended_in_both = client.request(
            "findCards",
            {"query": f'deck:"{target_deck}" note:"{target_model}" is:suspended'},
        )
        logger.info(
            "Suspended counts deck=%s model=%s deck+model=%s",
            len(suspended_in_deck),
            len(suspended_in_model),
            len(suspended_in_both),
        )

    for nid in note_id_list:
        infos = cards_by_nid.get(nid, [])
        if not infos:
            continue

        ladder_cards = [
            c
            for c in infos
            if c.get("deckName") == target_deck
            and (c.get("ord") in conj_ords or c.get("ord") == base_ord)
        ]
        mature_count = sum(1 for c in ladder_cards if card_interval(c) >= threshold)
        conj_cards = [
            c for c in infos if c.get("deckName") == target_deck and c.get("ord") in conj_ords
        ]
        active_conj = [c for c in conj_cards if not card_is_suspended(c)]
        desired = min(mature_count, len(conj_cards))

        if debug_stats:
            logger.info(
                "Stats nid=%s ladder=%s mature=%s conj=%s active=%s desired=%s",
                nid,
                len(ladder_cards),
                mature_count,
                len(conj_cards),
                len(active_conj),
                desired,
            )

        if len(active_conj) >= desired:
            continue

        candidates = [c for c in conj_cards if card_is_suspended(c)]
        if not candidates:
            continue

        picked = random.choice(candidates)
        card_id = picked.get("cardId")
        if card_id is None:
            continue

        logger.info("Unlocking nid=%s cardId=%s ord=%s", nid, card_id, picked.get("ord"))
        if not dry_run:
            client.request("unsuspend", {"cards": [card_id]})
        unlocked.append({"nid": nid, "card_id": card_id, "ord": picked.get("ord")})

    return {"notes": evaluated_count, "unlocked": len(unlocked), "details": unlocked}


def send_notification(cfg, summary, logger):
    notify_cfg = cfg.get("notification", {})
    notify_type = notify_cfg.get("type", "none")
    if notify_type == "none":
        return
    if notify_type == "command":
        command = notify_cfg.get("command")
        if not command:
            logger.warning("Notification command not configured")
            return
        cmd = [arg.replace("{summary}", summary) for arg in command]
        try:
            subprocess.run(cmd, check=False)
            logger.info("Notification command executed")
        except OSError as exc:
            logger.warning("Notification command failed: %s", exc)
        return
    if notify_type == "pushover":
        token = notify_cfg.get("token")
        user = notify_cfg.get("user")
        if not token or not user:
            logger.warning("Pushover notification missing token/user")
            return
        payload = urllib.parse.urlencode(
            {"token": token, "user": user, "message": summary}
        ).encode("utf-8")
        req = urllib.request.Request(
            "https://api.pushover.net/1/messages.json",
            data=payload,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10):
                logger.info("Pushover notification sent")
        except urllib.error.URLError as exc:
            logger.warning("Pushover notification failed: %s", exc)
        return

    logger.warning("Unknown notification type: %s", notify_type)


def main():
    parser = argparse.ArgumentParser(description="Unlock Anki conjugation cards")
    parser.add_argument(
        "--config",
        default="config.json",
        help="Path to configuration JSON (default: config.json)",
    )
    parser.add_argument("--dry-run", action="store_true", help="Do not unsuspend cards")
    args = parser.parse_args()

    cfg = load_config(args.config)
    logger = setup_logging(cfg)

    anki_cfg = cfg.get("anki", {})
    client = AnkiConnectClient(
        anki_cfg.get("connect_url", "http://127.0.0.1:8765"),
        anki_cfg.get("api_version", 6),
        timeout=anki_cfg.get("request_timeout_seconds", 10),
    )

    process_manager = AnkiProcessManager(anki_cfg.get("launch", {}), logger)
    launched = False
    post_sync_done = False

    try:
        launched = process_manager.maybe_launch(client=client)
        if not wait_for_anki(
            client,
            anki_cfg.get("startup_wait_seconds", 60),
            anki_cfg.get("poll_interval_seconds", 1),
            logger,
        ):
            return 2

        if not sync_collection(client, anki_cfg, logger, phase="before"):
            logger.error("Sync failed and is required; aborting")
            return 3
        time.sleep(anki_cfg.get("post_sync_settle_seconds", 2))

        results = unlock_conjugations(client, cfg, logger, dry_run=args.dry_run)
        summary = (
            f"Unlocked {results['unlocked']} conjugation cards across "
            f"{results['notes']} notes"
        )
        logger.info(summary)
        if not args.dry_run:
            time.sleep(anki_cfg.get("post_unlock_settle_seconds", 2))
            if sync_collection(client, anki_cfg, logger, phase="after"):
                post_sync_done = True
            else:
                logger.error("Post-run sync failed and is required")
        send_notification(cfg, summary, logger)
        return 0
    finally:
        if launched:
            if not args.dry_run and not post_sync_done:
                try:
                    time.sleep(anki_cfg.get("post_unlock_settle_seconds", 2))
                    sync_collection(client, anki_cfg, logger, phase="after")
                except Exception:
                    logger.warning("Post-run sync attempt failed during shutdown")
            process_manager.shutdown(client=client)


if __name__ == "__main__":
    sys.exit(main())
