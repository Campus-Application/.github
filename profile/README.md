<!-- CAMPUS-OVERVIEW:START -->

# 🎓 Campus Applications — Consolidated Overview

| Tool | Azure Operating Time | Frontend | Backend | Other / Notes |
|------|----------------------|-----------|----------|----------------|
| **Achievement Board** | Feb – Apr | [Frontend](https://github.com/Campus-Application/Achievement-Board-Frontend) [🟢](https://github.com/Campus-Application/Achievement-Board-Frontend/actions/runs/19741120296) | [Backend](https://github.com/Campus-Application/Achievement-Board-Backend) [🟢](https://github.com/Campus-Application/Achievement-Board-Backend/actions/runs/24825685423) |  |
| **CampBoard** | Aug – Jan | [Frontend](https://github.com/Campus-Application/CampBoard-Frontend) [🟢](https://github.com/Campus-Application/CampBoard-Frontend/actions/runs/24447636620) | [Backend](https://github.com/Campus-Application/CampBoard-Backend) [🟢](https://github.com/Campus-Application/CampBoard-Backend/actions/runs/18651148547) | [Runtime](https://github.com/Campus-Application/Campboard-Runtime) |
| **HackTheInka** | Okt | [Frontend](https://github.com/Campus-Application/HackTheInka-Frontend) [🟢](https://github.com/Campus-Application/HackTheInka-Frontend/actions/runs/26939661707) | [Backend](https://github.com/Campus-Application/HackTheInka-Backend) [🟢](https://github.com/Campus-Application/HackTheInka-Backend/actions/runs/19857989168) | [Old Version](https://github.com/Campus-Application/Hack-The-Inka-Frontend) |
| **Jump-In App** | Jul – Aug | [Frontend](https://github.com/Campus-Application/jump-in-frontend) | [Backend](https://github.com/Campus-Application/jump-in-backend) | [PHP Version](https://github.com/Campus-Application/jump-in-php) [🟢](https://github.com/Campus-Application/jump-in-php/actions/runs/25554935602), [Configuration](https://github.com/Campus-Application/jump-in-konfig) |
| **SchnuppiTool** | Jan – Dez | [Frontend](https://github.com/Campus-Application/Schnuppitool_Frontend) [🟢](https://github.com/Campus-Application/Schnuppitool_Frontend/actions/runs/26802802318) | [Backend](https://github.com/Campus-Application/SchnuppiTool_Backend) [🟢](https://github.com/Campus-Application/SchnuppiTool_Backend/actions/runs/26091806899) | [Old App](https://github.com/Campus-Application/SchnuppiTool) |
| **SpacePostOffice (Messe Tool)** | On demand | [Application](https://github.com/Campus-Application/spacepost) [🟢](https://github.com/Campus-Application/spacepost/actions/runs/18652027856) |  |  |
| **Zukunftstag** | Nov | [Frontend](https://github.com/Campus-Application/Zukunftstag-Frontend) [🟢](https://github.com/Campus-Application/Zukunftstag-Frontend/actions/runs/18651900964) |  |  |
| **Welcome Screen** | — | [Frontend](https://github.com/Campus-Application/WelcomeScreen-Frontend) [🟢](https://github.com/Campus-Application/WelcomeScreen-Frontend/actions/runs/25375887377) |  |  |
| **Raspberry Pi Tools** | — | [Management Tool](https://github.com/Campus-Application/Pi-manage-tool) |  |  |
| **Robot Karol (Schnuppertage)** | — | [Applikation](https://github.com/Campus-Application/robot-karol) |  |  |
| **Campus Party App** | — | [Frontend](https://github.com/Campus-Application/CampusParty-App-Frontend) | [Backend](https://github.com/Campus-Application/CampusParty-App-Backend) |  |


## ⚠️ Dependabot Alerts — Weekly Snapshot

_Note: only repositories with > 0 open alerts are listed. Archived tools are hidden._

| Tool | Repo | Build | Open | Critical | High | Moderate | Low |
|------|------|-------|-----:|--------:|-----:|---------:|----:|
| **Robot Karol (Schnuppertage)** | [Frontend](https://github.com/Campus-Application/robot-karol) |  | 171 | 3 | 82 | 67 | 19 |
| **Achievement Board** | [Frontend](https://github.com/Campus-Application/Achievement-Board-Frontend) | [🟢](https://github.com/Campus-Application/Achievement-Board-Frontend/actions/runs/19741120296) | 117 | 2 | 53 | 51 | 11 |
| **Campus Party App** | [Frontend](https://github.com/Campus-Application/CampusParty-App-Frontend) |  | 75 | 5 | 29 | 32 | 9 |
| **Jump-In App** | [Repository](https://github.com/Campus-Application/jump-in-konfig) |  | 60 | 1 | 23 | 27 | 9 |
| **SchnuppiTool** | [Frontend](https://github.com/Campus-Application/Schnuppitool_Frontend) | [🟢](https://github.com/Campus-Application/Schnuppitool_Frontend/actions/runs/26802802318) | 54 | 0 | 23 | 28 | 3 |
| **Jump-In App** | [Frontend](https://github.com/Campus-Application/jump-in-frontend) |  | 52 | 1 | 18 | 24 | 9 |
| **CampBoard** | [Repository](https://github.com/Campus-Application/Campboard-Runtime) |  | 22 | 1 | 10 | 6 | 5 |
| **Welcome Screen** | [Frontend](https://github.com/Campus-Application/WelcomeScreen-Frontend) | [🟢](https://github.com/Campus-Application/WelcomeScreen-Frontend/actions/runs/25375887377) | 17 | 0 | 8 | 7 | 2 |
| **Achievement Board** | [Backend](https://github.com/Campus-Application/Achievement-Board-Backend) | [🟢](https://github.com/Campus-Application/Achievement-Board-Backend/actions/runs/24825685423) | 3 | 0 | 0 | 2 | 1 |
| **HackTheInka** | [Frontend](https://github.com/Campus-Application/HackTheInka-Frontend) | [🟢](https://github.com/Campus-Application/HackTheInka-Frontend/actions/runs/26939661707) | 1 | 0 | 0 | 1 | 0 |


<!-- CAMPUS-OVERVIEW:END -->

---

## How to update this overview

The section above is generated automatically. 
Do not edit anything between `<!-- CAMPUS-OVERVIEW:START -->` and `<!-- CAMPUS-OVERVIEW:END -->` manually.

To add, remove or change an application, edit `.github/data/tools.yaml`:

```yaml
- name: "My Tool"
  azure_operating_time: "Mar – Jun"
  repos:
    frontend: "https://github.com/Campus-Application/my-tool-frontend"
    backend: "https://github.com/Campus-Application/my-tool-backend"
    other:
      - label: "Configuration"
        url: "https://github.com/Campus-Application/my-tool-config"
```

Use `archived: true` to hide old tools from the overview and the Dependabot table.

The GitHub Action updates this README every Monday and can also be started manually from the Actions tab. It reads `data/tools.yaml`, checks build status and Dependabot alerts, then updates `profile/README.md`.

### Token for Dependabot alerts

The workflow uses the repository secret `SECURITY_READ_TOKEN` as `GH_TOKEN`. This token is currently generated by a user account, so it can stop working if that user leaves the organization, loses access, deletes the token or the token expires.

If the action starts failing with `401`, `403`, missing Dependabot data or empty build-status data, generate a new token from a GitHub user that has access to all relevant `Campus-Application` repositories. The token needs read access for repository metadata, GitHub Actions runs and Dependabot alerts. Then replace the value of the `SECURITY_READ_TOKEN` secret in GitHub and rerun the workflow manually.

Never commit the token to the repo. Only store it as a GitHub secret.

For more Information please consult the Step-By-Step Guide here: https://ictcampusnet-my.sharepoint.com/personal/einkaufcloud_ict-campus_net/_layouts/Doc.aspx?sourcedoc={B13246E9-0C4B-4D2D-857B-817FB7C4D15A}&wd=target%28Campus%20GIT%20%28GitHub%5C%29.one%7C84B47903-69A1-4AC9-BFFD-2D99F35DF362%2FNeues%20Repo%20in%20Campus%20Application%20aufnehmen%7C7F27BCCF-4393-45DA-8ED7-024DC8795142%2F%29&wdpartid={E3F70D30-6B6E-0597-1179-6AB0F0A0F0C8}{1}&wdsectionfileid={CA661DA0-CAAF-46D8-9BA1-4373F197A15D}&end
