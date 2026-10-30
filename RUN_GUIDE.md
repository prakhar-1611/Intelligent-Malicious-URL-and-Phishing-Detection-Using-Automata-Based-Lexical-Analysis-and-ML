# How to Run the Phishing Detector

Last updated: 30 October 2026

## What you need

On your laptop everything below is already in place, so you can go straight to Quick start.

| Item | Where it lives | Already set up on your laptop |
| --- | --- | --- |
| Project folder | `C:\Users\Asus\Compiler Lab Project` | Yes |
| Python 3.13 environment | the `.venv` folder inside the project | Yes |
| Node.js 20 or newer | installed on Windows | Yes |
| Dashboard packages | `web\node_modules` | Yes |
| Trained model files | `artifacts\model.joblib`, `artifacts\model_domain_only.joblib`, `artifacts\corpus_symtab.json`, `artifacts\corpus_symtab_domain_only.json` | Yes |

The model files are not in git, so they exist only on your laptop. On any other computer, copy the four
`artifacts` files across (or retrain, see Rebuild every result) and run this one-time setup in the project folder:

```
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
cd web
npm install
```

## Quick start

Double-click `start.bat` in the project folder; the site opens at http://localhost:5173 a few seconds later.

1. Open File Explorer and go to `C:\Users\Asus\Compiler Lab Project`.
2. Double-click `start.bat`.
3. Two black windows open: "Phishing API" and "Phishing dashboard". Leave both open while you use the site.
4. Your browser opens http://localhost:5173. If it opens before the dashboard is ready, wait five seconds and refresh.

`start.bat` uses the project's own Python (`.venv`), which is what loads the trained model. If `web\node_modules`
is missing, it runs `npm install` first, which adds about a minute the first time.

## Manual start

If you prefer to start it yourself, open two PowerShell terminals and paste one block into each.

Terminal 1, the API (port 8000):

```
cd "C:\Users\Asus\Compiler Lab Project"
.\.venv\Scripts\python.exe -m uvicorn api.main:app --port 8000
```

Wait for the line "Application startup complete".

Terminal 2, the dashboard (port 5173):

```
cd "C:\Users\Asus\Compiler Lab Project\web"
npm run dev
```

Then open http://localhost:5173 in your browser.

Always start the API with `.\.venv\Scripts\python.exe`, never with plain `uvicorn`: plain `uvicorn` uses the global
Python, which has no trained model, and the site silently falls back to a weaker heuristic.

## Check it works

The site is running correctly when the footer of every page says "Model: xgboost (calibrated)" and the header
shows a green "API online".

- For a second check, open http://127.0.0.1:8000/health. It should show `"status": "ok"`,
  `"model": "xgboost (calibrated)"`, 109 DFA states and 187 features.
- "heuristic-fallback (no trained model)" anywhere means the API was started the wrong way. See Troubleshooting.
- A quick test: on the Analyze page, click the "Hidden IP address" example. It should come back Malicious.

## Using the site

The dashboard has seven pages in the top bar. The site never opens or fetches any URL you give it, and shows every
URL defanged (`hxxp://example[.]com`).

| Page | What you do there |
| --- | --- |
| Analyze | Paste one URL, or click an example, to get the verdict, tokens, flags and symbol table |
| Explain | See which features pushed the score up or down, and the characters behind each one |
| Automata Lab | Pick a token rule or type a regex, and step through regex, NFA, DFA and minimal DFA |
| Live Trace | Watch the scanner walk the minimal DFA one character at a time (Play, step, speed) |
| Batch | Paste many URLs, upload a CSV, or load the 15-URL demo set; export results as CSV |
| Email | Paste a raw email or upload a `.eml` file (up to 1 MB); get the verdict, headers, MIME parts and links |
| Results | Every experiment number and figure, read from `artifacts\results` |

To get a `.eml` file from Gmail, open the email, click the three dots, then "Download message". On the Email page,
"Try a sample" loads the two built-in examples in one click.

## Run the tests and the build

All 567 tests should pass; this takes under a minute.

```
cd "C:\Users\Asus\Compiler Lab Project"
.\.venv\Scripts\python.exe -m pytest -q
```

Expected last line: "567 passed, 1 warning". The one warning comes from a FastAPI library inside `.venv`, not from
the project.

To check that the dashboard compiles (type check plus production build, about 30 seconds):

```
cd "C:\Users\Asus\Compiler Lab Project\web"
npx tsc -b
npm run build
```

## Rebuild every result

You only need this to retrain from scratch; it takes about 45 to 60 minutes and replaces the model and every file in
`artifacts\results`.

1. Put the two legitimate-email datasets in place (they are not in git):
    1. Kaggle "Enron Email Dataset" (`archive.zip`): unzip `emails.csv` into `data\raw\email_ham\enron\`
    2. Kaggle "SpamAssassin" (`spam_assassin.csv.zip`): unzip `spam_assassin.csv` into `data\raw\email_ham\spamassassin\`
2. Back up the current model and results first, so you can switch back (copy the `artifacts` folder somewhere safe).
3. Run the full pipeline from the project folder:

    ```
    cd "C:\Users\Asus\Compiler Lab Project"
    .\.venv\Scripts\Activate.ps1
    .\scripts\reproduce.ps1
    ```

4. Restart the API afterwards (close its window and run `start.bat` again), because a running API keeps the old
   model in memory.

`reproduce.ps1` downloads fresh PhishTank, URLhaus, OpenPhish, Tranco and Hacker News lists, so its numbers will
differ slightly from the ones in the paper. The paper's numbers were produced from the Review 2 data with the same
split kept for every existing domain. The pre-retrain model and results are backed up in
`data\processed\backup_before_email_ham`.

## The research paper

The paper is in `docs\paper` in three forms, all with the same text.

| File | Use it for |
| --- | --- |
| `paper.pdf` | Reading, printing and submitting |
| `paper.docx` | Editing in Word |
| `main.tex` | Overleaf: open the IEEE Access template, paste this file over its `.tex`, and upload `shap_global.png`, `scaling.png` and `redos.png` |

If you change a number in the Word file, the PDF does not update by itself: in Word, use File, Save As, PDF.

## Troubleshooting

| What you see | Cause | Fix |
| --- | --- | --- |
| Footer says "heuristic-fallback (no trained model)" | API started with plain `uvicorn` (global Python), or the model files are missing | Close the API window, check `artifacts\model.joblib` exists, start with `start.bat` or the Manual start command |
| Red "API unreachable" banner, "API offline" | The API window is closed or crashed | Run `start.bat` again, or Terminal 1 of Manual start |
| "address already in use" or "Port 8000 is in use" | An old API or dashboard is still running | See the commands below this table |
| "429 Too Many Requests" | Rate limit: 60 requests a minute (email 20, batch 10) | Wait one minute and try again |
| Email page: "larger than 1 MB" | The email is over the size limit | Remove large attachments, or paste only the headers and body text |
| "npm is not recognized" | Node.js is not installed | Install Node.js 20 or newer from nodejs.org, then reopen the terminal |
| A Mac shows heuristic-fallback | LightGBM and XGBoost need OpenMP | Run `brew install libomp`, and start with `.venv/bin/python -m uvicorn api.main:app --port 8000` |

To free a busy port, run this in PowerShell (8000 for the API, 5173 for the dashboard), then start again:

```
Get-NetTCPConnection -LocalPort 8000 -State Listen | Select-Object OwningProcess
Stop-Process -Id <the number shown>
```

## Stopping the project

Close the two windows ("Phishing API" and "Phishing dashboard"), or click into each and press Ctrl+C. Closing the
browser tab alone leaves both servers running in the background. Restarting your laptop also stops them; run
`start.bat` to bring them back.
