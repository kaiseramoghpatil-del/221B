# 221B — 4-minute demo script

**Goal:** within 30 seconds the judges know what 221B does. By the end they have seen it prove itself on a case they
chose.

## Before you go on (5 minutes earlier)
- Start the server: `python -m uvicorn backend.api.app:app --port 8221`. Open http://localhost:8221.
- Open the demo case once (warms everything), then go back to the start page.
- Pre-open a second tab on `/?page=verify`.
- Browser zoom 110–125% so the verdict reads on a shared screen. Close other tabs and notifications.
- Fallback: the 90-second recorded video (see "Recording" at the bottom), plus screenshots in a folder.

## Script

| Time | Do | Say (plain, short) |
|---|---|---|
| 0:00 | Start page | "Four days of logs from a small company: about 49,000 events. Somewhere in there an intruder got in. Which of these lines is the break-in?" |
| 0:15 | Click **Open demo case** | "221B reads the raw files the way it would read yours: auth logs, web logs, network flows, an audit trail." |
| 0:25 | Point at the **funnel** | "49,000 events. 141 detector hits. 11 that connect. **One incident.**" |
| 0:35 | Read the **verdict** aloud | "h.petrov's account was taken over from this address, used to reach the database, and 3.6 GB went back out to the same address." |
| 0:50 | Click **Isolated alerts** | "This is the same detector output the way a normal console shows it: 42 alerts, one per rule. Which ones matter, and are they one story? You can't tell from this." Click **Reconstructed** again. |
| 1:10 | Click **Replay the attack** (let it run) | Narrate the chips as they appear: "Password spray from the internet. Then a successful login from that same address. Recon commands. A network scan. Root. An SSH key planted. Hop to app, hop to the database. Data gathered. Data out." |
| 1:50 | Click finding **2 (Break-in)** | "Every sentence is a link. This is the rule that fired, what it could otherwise be, and the exact line in auth.log with the 35 failed attempts that came before it." Press Esc. |
| 2:15 | Scroll to **Exhibit C** | "Just as important is what it did *not* accuse. This IP made 2,500 failed logins, the loudest thing in the logs, and it never got in. The nightly scanner and the backup job are cleared too, each with evidence." |
| 2:40 | Back to start page, **Generate a case nobody has seen**, ask a judge for a number, choose **Password guessing**, **10 rotating** IPs, stealth high | "Give me any number." Type it. "This case did not exist a second ago. Ten attacker IPs, slow and quiet." |
| 3:05 | Case opens: read the new verdict | "Different account, different addresses, same reconstruction." |
| 3:15 | Click **Reveal the answer key** | "The generator kept the truth hidden. Entry address: match. Account: match. Host the data came from: match. And the same detector output read three ways: every hit as an alert, hits grouped by time, or 221B's single incident." (Read the numbers off the screen; they differ per case.) |
| 3:40 | Switch to the **How it was tested** tab | "We ran 300 of these: found 252 out of 252, no false alarm in 48 clean weeks. And this box says what the numbers don't prove: we built the detectors on this generator." |
| 3:55 | Stop | "221B: who got in, how, what they touched, and the proof, line by line." |

## If something goes wrong
- **A judge's seed gives a miss or an extra incident:** don't hide it. "Here's where it falls short." Open the Verify page's *Where it fell short* list: the same kinds of cases are already documented there.
- **Server down or slow:** switch to the recorded video. Every UI state is deep-linkable, so screenshots can stand in.
- **Asked "is this just an LLM?":** "No model makes any decision. Detection, linking, scoring and the text are deterministic; every sentence is generated from the evidence and cites it."
- **Asked "isn't it tested on its own data?":** "Yes, and the page says so. That's why we wrote one attack type after freezing the engine and tested it once: an insider stealing data with their own account. 221B put the theft at the top of the watchlist 90 times out of 90, but never built it into an incident. That's on the Verify page too, along with the fix we'd make next."

## Recording the 90-second fallback video
1. Demo case, funnel and verdict (15 s).
2. Replay (25 s).
3. Evidence drawer for the break-in (15 s).
4. Exhibit C (10 s).
5. New seed, then reveal (20 s).
6. Verify page headline (5 s).

Record at 1920×1080, 125% zoom, no narration gaps longer than 2 seconds.
