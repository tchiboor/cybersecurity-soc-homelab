# Part 3 Lab Notes — Attacking the AI SOC Agent

## Goal

Test whether attacker-controlled log content can influence the AI-assisted triage advice while keeping Python-owned evidence, severity, and verdict intact.

## Core Design Rule

Python owns the facts and verdict. The model only advises.

## Baseline

- Current branch:
- Current date:
- Current known-good command:
- Current known-good test result:

## Experiments

### Experiment 1 — Baseline alert

Command:

Result:

Notes:

### Experiment 2 — Prompt injection inside alert field

Command:

Result:

What changed:

What stayed trustworthy:

### Experiment 3 — Hardened agent

Command:

Result:

What improved:

## Screenshots

- SS1:
- SS2:
- SS3:
- SS4:

## Lessons Learned

-