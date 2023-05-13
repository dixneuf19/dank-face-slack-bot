import logging
import os
from typing import Any

import httpx
from fastapi import FastAPI, Request, Response
from path import Path
from pydantic import ValidationError
from slack_bolt import App
from slack_bolt.adapter.fastapi import SlackRequestHandler
from slack_bolt.context.ack import Ack
from slack_bolt.oauth.oauth_settings import OAuthSettings
from slack_sdk import WebClient
from slack_sdk.oauth.installation_store import FileInstallationStore
from slack_sdk.oauth.state_store import FileOAuthStateStore

from dank_face_slack_bot.models import Event, FuzzyOctoDiscoResponse

FUZZY_OCTO_DISCO_ADDRESS = f'{os.getenv("FUZZY_OCTO_DISCO_HOST", default="http://localhost")}:{os.getenv("FUZZY_OCTO_DISCO_PORT", default="8080")}'
FUZZY_OCTO_DISCO_TIMEOUT_SECONDS = int(
    os.getenv("FUZZY_OCTO_DISCO_TIMEOUT_SECONDS", default="60")
)
SLACK_BOT_TOKEN = os.environ.get("SLACK_BOT_TOKEN")

FIND_FACES_PIC_FOLDER = os.environ.get("FIND_FACES_PIC_FOLDER", default="/tmp")

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=LOG_LEVEL)

if SLACK_BOT_TOKEN:
    logging.info("using bot token")
    app = App(
        token=SLACK_BOT_TOKEN, signing_secret=os.environ.get("SLACK_SIGNING_SECRET")
    )

else:
    logging.info("using oauth")
    oauth_settings = OAuthSettings(
        client_id=os.environ.get("SLACK_CLIENT_ID"),
        client_secret=os.environ.get("SLACK_CLIENT_SECRET"),
        scopes=[
            "app_mentions:read",
            "files:write",
            "files:read",
            "reactions:write",
            "chat:write",
        ],
        installation_store=FileInstallationStore(base_dir="./data"),
        state_store=FileOAuthStateStore(expiration_seconds=600, base_dir="./data"),
        install_page_rendering_enabled=True,
    )

    # Initializes your app with your bot token and signing secret
    app = App(
        signing_secret=os.environ.get("SLACK_SIGNING_SECRET"),
        oauth_settings=oauth_settings,
    )

app_handler = SlackRequestHandler(app)


# TODO: add global error handler

ERROR_EMOJI = "face_with_head_bandage"
NOTHING_FOUND_EMOJI = "face_with_monocle"
SUCCESS_EMOJI = "smiling_face_with_3_hearts"


@app.event({"type": "message", "subtype": "file_share"})
# See https://github.com/slackapi/bolt-python/blob/main/slack_bolt/kwargs_injection/args.py for typing
def handle_file_shared_events(
    ack: Ack, client: WebClient, event: dict[str, Any] | None, logger: logging.Logger
) -> None:
    try:
        e = Event.parse_obj(event)
    except ValidationError as error:
        logger.error(f"Failed to parse event: {error}")
        return

    ack()
    for file in e.files:
        # TODO: actually webp file can have png extension
        if file.filetype not in ("jpg", "png", "webm", "gif"):
            logger.info("File is not an image")
            client.reactions_add(
                name=ERROR_EMOJI,
                channel=e.channel,
                timestamp=e.event_ts,
            )
            return

        # TODO: handle error when downloading the file
        # download the file with a stream via httpx
        file_path = f"{FIND_FACES_PIC_FOLDER}/{file.id}.{file.filetype}"

        # TODO: use stream to avoid loading the whole file in memory
        with open(file_path, "wb") as f:
            res = httpx.get(
                file.url_private,
                # TODO: how to get the token with oauth?
                headers={"Authorization": f"Bearer {SLACK_BOT_TOKEN}"},
                follow_redirects=True,
            )
            res.raise_for_status()
            f.write(res.content)

        try:
            res = httpx.get(
                f"{FUZZY_OCTO_DISCO_ADDRESS}/faces",
                params={"pic_path": file_path},
                timeout=FUZZY_OCTO_DISCO_TIMEOUT_SECONDS,
            )
            res.raise_for_status()
            try:
                result = FuzzyOctoDiscoResponse.parse_obj(res.json())
            except ValidationError as error:
                logger.error(f"Failed to parse fuzzy-octo-disco response: {error}")
                raise error

            if result.status == "SUCCESS":
                logger.debug(
                    f"Found {result.nbFaces} faces. Sending on channel {e.channel} and thread {e.event_ts}"
                )
                client.reactions_add(
                    name=SUCCESS_EMOJI,
                    channel=e.channel,
                    timestamp=e.event_ts,
                )
                uploads = []
                for i in range(int(result.nbFaces)):
                    result_path = result.paths[i]
                    try:
                        uploads.append(client.files_upload_v2(file=result_path))
                    except Exception as error:
                        logger.warning(f"Failed to upload face {i}: {error}")
                        pass
                    finally:
                        try:
                            # Remove the file
                            # Path(result.paths[i]).remove_p()
                            pass
                        except Exception as error:
                            logger.warning(f"Failed to remove face {i}: {error}")
                            pass
                # TODO: handle all uploads failed
                msg = "".join(
                    [f"<{upload['file']['permalink']}| >" for upload in uploads]
                )
                client.chat_postMessage(
                    text=msg,
                    channel=e.channel,
                    thread_ts=e.event_ts,
                )

            elif result.status in ("NO_FACE_FOUND", "FAILED_ALL_FACES"):
                logger.info("No faces found")
                client.reactions_add(
                    name=NOTHING_FOUND_EMOJI,
                    channel=e.channel,
                    timestamp=e.event_ts,
                )
            else:
                client.reactions_add(
                    name=ERROR_EMOJI,
                    channel=e.channel,
                    timestamp=e.event_ts,
                )
                logger.error(
                    f"Received {result.status} from fuzzy-octo-disco: {result.message}"
                )
        except httpx.RequestError as exc:
            logger.error(
                f"An error occurred while requesting {exc.request.url!r}: {exc}"
            )
            client.reactions_add(
                name=ERROR_EMOJI,
                channel=e.channel,
                timestamp=e.event_ts,
            )
        finally:
            try:
                Path(file_path).remove_p()
            except Exception as error:
                logger.warning(f"Failed to remove the original file: {error}")
            pass


api = FastAPI()


@api.post("/slack/events")
async def endpoint(req: Request) -> Response:
    return await app_handler.handle(req)


@api.get("/slack/install")
async def install(req: Request) -> Response:
    return await app_handler.handle(req)


@api.get("/slack/oauth_redirect")
async def oauth_redirect(req: Request) -> Response:
    return await app_handler.handle(req)


@api.get("/health")
async def get_health() -> dict[str, str]:
    return {"message": "OK"}
