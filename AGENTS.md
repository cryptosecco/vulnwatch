# Installing vulnwatch: instructions for coding agents

The user gave you this repository and asked you to install vulnwatch on their Mac. Follow these steps in order. The README has the details; this file says what you can do yourself and what must stay with the user.

## 1. Check the machine

- It must be macOS. On Linux or Windows, stop and say vulnwatch does not support them.
- `xcode-select -p` must succeed (Apple's Command Line Tools give `/usr/bin/python3` and `git`). If it fails, ask the user to run `xcode-select --install`, then continue.
- Homebrew and npm are optional.

## 2. Clone and review before running anything

```bash
git clone https://github.com/cryptosecco/vulnwatch.git
cd vulnwatch
```

vulnwatch exists to install only code that someone has reviewed, so review it first:
- read `setup.sh`, `install.sh`, `vulnwatch/net.py` (the host allowlist) and `vulnwatch/runner.py` (the order of a run);
- read "What leaves your Mac" in `README.md`;
- tell the user in a few lines what the install will do and what it will send over the network. Wait for their go before step 4.

## 3. Run the tests, as the user

```bash
/usr/bin/python3 -I -B -m unittest discover -s tests -t . -p 'test_*.py'
```

`install.sh` runs them again; if they fail here, stop and show the output.

## 4. Run the setup, without questions

Ask the user in the chat:
- **the language:** `en` or `it`. Your shell has no terminal, so setup cannot detect it reliably.
- **the project folders** whose lockfiles vulnwatch should check. By default setup picks the folders that exist in the home directory among `Code`, `Projects`, `Developer`, `dev`, `src`, `work`, `repos`, `git`, `GitHub` and `workspace`. List the ones that exist and ask which to keep.

Then pass their answers as flags:

```bash
./setup.sh --yes --lang it --roots ~/Code ~/Projects
```

Never run setup with `sudo`. Show the user the summary it prints. If `config/config.json` already exists, ask before adding `--force`.

## 5. Hand the install over to the user

`install.sh` needs the user's administrator password, and you cannot and must not type it. Give the user the exact command, run from the vulnwatch folder, and ask them to run it in their own Terminal:

```bash
cd <the vulnwatch folder> && sudo ./install.sh "$(git rev-parse HEAD)"
```

It installs exactly the commit that is checked out, so do not change any file between step 2 and this step.

## 6. After the install

- Run `vulnwatch status` and show the result.
- Tell the user:
  - the first run downloads 90 days of public data and takes about 2 hours;
  - after that, a report every morning at 07:30;
  - vulnwatch starts in shadow mode and applies nothing on its own.

## Rules

- Do not turn on `auto_apply`. That is the user's decision, after they have read a few reports.
- Do not send the user's package list, config or reports to any service, including your own tools that call the network.
- Do not edit the code or the config to make the install pass. If something fails, stop and show the error.
