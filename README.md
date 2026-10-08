# Fulton Family Conferences

Family conference records for Fulton Community School & Farm. Teachers fill in the Family Conference form for each child, upload completed paper forms to have them read, and follow each child's conferences over the years.

## How it runs

- **Web page** `index.html`, published with GitHub Pages at https://renee-creator.github.io/fulton-conferences/
- **Server** `server.js`, running on Render at https://fulton-conferences.onrender.com. Open that address in a browser to see a status page.
- **Records** are kept as files in the private repository `fulton-conference-records`. Every change is saved there with the teacher's name, so earlier versions can always be recovered from GitHub's history.

This repository holds code only. It never holds children's information or keys.

## Server settings on Render

| Setting | What it holds |
|---|---|
| `TEACHER_PASSCODES` | Each teacher's name and passcode, separated by commas, like `Hannah=maple garden 42,Chris=river stone 7`. Passcodes need at least 6 characters. A single shared passcode with no name also works, and edits then show as Staff. Removing a teacher signs them out. |
| `GITHUB_TOKEN` | A fine-grained GitHub token with Contents read and write on `fulton-conference-records` only |
| `ANTHROPIC_API_KEY` | The same key TREE uses |
| `RECORDS_REPO` | Optional. Defaults to `renee-creator/fulton-conference-records` |
| `ALLOWED_ORIGINS` | Optional. Extra websites allowed to use the server |

## Reading forms

Uploaded forms are read with Claude Haiku. The "Read again more carefully" button uses Claude Sonnet for hard handwriting. Forms are sent to Anthropic only to be read, and Anthropic does not use them to train its AI.

## Editing the page

The page is built from two parts in `src`. `app.html` is the conference app and `shim.html` adds sign-in and the connection to the server. After changing either one, run `python3 tools/build.py` to rebuild `index.html`.

## Free plan notes

The Render server sleeps after 15 quiet minutes. The first visit after that takes about a minute while it wakes, and the page says so. Typing is gathered and saved to GitHub within about 15 seconds.
