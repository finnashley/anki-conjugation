# anki-conjugation
Unlocks suspended conjugation cards in Anki based on a maturity ladder.

## Requirements
- Anki Desktop with the AnkiConnect add-on enabled.
- Access to AnkiConnect at `http://127.0.0.1:8765`.
- Headless environments should install `xvfb` if using the default launch command.

## Setup
1) Create a configuration file:
```
cp config.example.json config.json
```
2) Edit `config.json` to set your deck, model, base card ordinal, and conjugation ordinals.
3) Run the script:
```
.venv/bin/python anki_conjugation_unlocker.py --config config.json
```

## Configuration notes
- `base_card_ord` is typically `0`. `conjugation_card_ords` should list the template ordinals used for conjugations.
- Set `anki.launch.enabled` to `false` if you manage Anki separately.
- `anki.launch.restart_if_running` defaults to restarting any running Anki before sync. Use `anki.launch.shutdown_match` to control which related processes are terminated.
- `anki.launch.sync_grace_seconds` controls how long we wait after sending SIGINT (Ctrl-C) to let Anki sync on exit before escalating to SIGTERM/SIGKILL.
- Set `anki.sync_after_run` to `true` if you want an explicit AnkiConnect sync after unlocking. `anki.post_unlock_settle_seconds` controls the wait before that sync.
- Set `debug_stats` to `true` if you want per-note ladder stats logged while diagnosing unlock behavior.
- If AnkiConnect times out on large collections, increase `anki.request_timeout_seconds` or reduce `cards_info_batch_size`.
- Use `debug_limit_notes` to cap how many notes are processed during diagnosis runs.
- If you want deterministic selection, set `random_seed`.

## Scheduling (systemd)
Install the user timer and service:
```
mkdir -p ~/.config/systemd/user
cp systemd/anki-conjugation.service ~/.config/systemd/user/
cp systemd/anki-conjugation.timer ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now anki-conjugation.timer
```

## Scheduling (cron)
Example daily run at 7am:
```
0 7 * * * /home/$USER/anki-conjugation/.venv/bin/python /home/$USER/anki-conjugation/anki_conjugation_unlocker.py --config /home/$USER/anki-conjugation/config.json
```
