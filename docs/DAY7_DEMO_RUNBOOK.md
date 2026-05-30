# Day 7 Demo Runbook

This runbook is for the hackathon demo. It uses the local lab Wazuh data path and avoids third-party SIEM access.

## Demo Goal

Show that the MVP reduces Wazuh alert noise, groups related alerts, enriches with local IOCs, creates case context, and protects SOAR actions with approval controls.

## Flow

1. Login with the seeded admin.
2. Open Overview and show executive metrics:
   - raw alerts
   - analyst items
   - grouped duplicates
   - solved vs unsolved cases
3. Open AI Triage.
   - Show queue filters.
   - Open an alert detail.
   - Show raw event, evidence, investigation steps, containment steps, and resolution criteria.
4. Open Correlation Groups.
   - Show grouped related Wazuh alerts.
   - Highlight representative alert, alert count, signal, risk, and suppression reason.
5. Open Settings -> Threat Intel.
   - Add a local IOC from the lab.
   - Return to alert detail and run local IOC enrichment.
6. Open Case Management.
   - Raise or create a case.
   - Add a timeline investigation note.
   - Move the case through investigation/resolved states.
7. Open SOAR Automation.
   - Request a containment approval.
   - Show it appears as `pending_approval`.
   - Approve or reject as admin.
8. Open Admin.
   - Show users, active/inactive state, and role assignment controls.
   - Demonstrate viewer revoke by changing a user to viewer or deactivating them.

## n8n Setup Needed For Live SOAR Dispatch

Run n8n on the Wazuh/lab host or another lab host:

```bash
docker volume create n8n_data
docker run -d --name n8n --restart unless-stopped \
  -p 5678:5678 \
  -e N8N_HOST=0.0.0.0 \
  -e N8N_PORT=5678 \
  -e N8N_PROTOCOL=http \
  -v n8n_data:/home/node/.n8n \
  n8nio/n8n:latest
```

Create a webhook workflow in n8n and copy the production webhook URL into `.env`:

```bash
N8N_WEBHOOK_URL=http://<n8n-host>:5678/webhook/<workflow-path>
```

Restart the backend after setting the URL. Non-destructive workflows can dispatch directly. Containment workflows are held for admin approval first.

## Demo Evidence

Screenshots are stored under `demo/screenshots/`.

To regenerate sanitized screenshots:

```bash
npm exec --package=playwright -- node scripts/capture_demo_screenshots.mjs
```

The small browser-based walkthrough is stored at `demo/video/demo-flow.html`.

## Current Remaining Hardening

- Add Shuffle connector templates.
- Add external threat-intel adapters for VirusTotal, AbuseIPDB, OTX, and MISP.
- Add long-range analytics snapshots for 7/15/30/365 day views.
- Add evidence attachments to cases.
- Add Docker Compose packaging for backend, frontend, and persistent DB volume.
