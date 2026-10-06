# Mutation Testing — Noor (Specialization B)

## What I did and why
I used mutation testing to check if my tests are actually good, not just "green".
Coverage only tells you a line ran. It does not tell you a test really checks it.
Mutation testing breaks the code on purpose (this is called a "mutant") and runs
the tests. If a test fails, the mutant is "killed" (good). If all tests still pass,
the mutant "survived", which means my tests have a gap.

I ran it on my own watermarking method, 

## How I set it up
I used `mutmut` (the tool from Lecture 2). I installed it with `pip install 'mutmut<3'`.
The config is in `server/setup.cfg`: it mutates `src/tiled_visible_watermark.py` and
runs only that method's tests. To reproduce:

```
cd server
mutmut run
mutmut results
```

## What I got
mutmut made 169 mutants. With my original 17 tests (and high coverage), 81 survived.
So my coverage was high, but my tests were not really checking a lot of the behaviour.

## What I found and fixed
The survivors that mattered were in `read_secret`, the part that reads the watermark
back. It is supposed to skip a broken token and keep looking for a real one. Two
mutants showed me this was not tested:

- **#156** changes `continue` to `break` on a token that has no `|` separator.
- **#163** changes `continue` to `break` on a token with broken base64.

Both mean the same thing: if a broken token comes before the real one, the reader
would stop and never find the real watermark. So an attacker could put a fake token
first and hide who the document belongs to. My old tests never had a "broken token
before a good one" case, so these two survived.

I added two tests in `test/test_tiled_mutation_kills.py`. Each one puts a broken
token first and a valid token after, and checks that the real secret is still read.
They kill #156 and #163. After adding them, survivors went from 81 to 79 (I re-ran
mutmut to confirm).

## The rest of the survivors (my analysis)
I did not try to kill all 79. Most of them are not real gaps:

- Most are **layout/geometry mutants**. They change the tiling numbers (spacing,
  margins, font size), so the watermark looks a bit different, but the secret is
  still stamped and still readable. That is the method's real job, so these do not
  break anything, and no test should pin the exact spacing.
- **#5** changes the `_SUFFIX` constant. Both writing and reading use the same
  constant, so the watermark still round-trips. This is an **equivalent mutant** — it
  can never be killed, and that is correct.
- **#77** (`>` to `>=`) and **#48** (single vs multi-page) only differ at an edge case
  I cannot realistically hit, so I left them as well.

## What I learned
Coverage said my code ran, but mutation showed my tests did not check the reader's
robustness. The useful result was 2 real gaps, not the score. Chasing a high kill
rate here would just mean fighting equivalent mutants. The real skill was telling the
real gaps apart from the equivalent mutants, and only fixing the ones that matter.
