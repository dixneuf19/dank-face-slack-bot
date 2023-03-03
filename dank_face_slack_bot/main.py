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
from slack_sdk import WebClient

from dank_face_slack_bot.models import Event, FuzzyOctoDiscoResponse

# from slack_bolt.oauth.oauth_settings import OAuthSettings
# from slack_sdk.oauth.installation_store import FileInstallationStore
# from slack_sdk.oauth.state_store import FileOAuthStateStore

FUZZY_OCTO_DISCO_ADDRESS = f'{os.getenv("FUZZY_OCTO_DISCO_HOST", default="http://localhost")}:{os.getenv("FUZZY_OCTO_DISCO_PORT", default="8080")}'
FUZZY_OCTO_DISCO_TIMEOUT_SECONDS = int(
    os.getenv("FUZZY_OCTO_DISCO_TIMEOUT_SECONDS", default="60")
)
SLACK_BOT_TOKEN = os.environ.get("SLACK_BOT_TOKEN")

# TODO: use oauth everywhere
# oauth_settings = OAuthSettings(
#     client_id=os.environ.get("SLACK_CLIENT_ID"),
#     client_secret=os.environ.get("SLACK_CLIENT_SECRET"),
#     scopes=["app_mentions:read", "file:write", "file:read", "reactions:write"],
#     installation_store=FileInstallationStore(base_dir="./data"),
#     state_store=FileOAuthStateStore(expiration_seconds=600, base_dir="./data"),
#     install_page_rendering_enabled=False,
# )

# # Initializes your app with your bot token and signing secret
# app = App(
#     signing_secret=os.environ.get("SLACK_SIGNING_SECRET"), oauth_settings=oauth_settings
# )

app = App(token=SLACK_BOT_TOKEN, signing_secret=os.environ.get("SLACK_SIGNING_SECRET"))
app_handler = SlackRequestHandler(app)

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=LOG_LEVEL)

# TODO: add global error handler


# @app.event("file_shared")
@app.event({"type": "message", "subtype": "file_share"})
# See https://github.com/slackapi/bolt-python/blob/main/slack_bolt/kwargs_injection/args.py for typing
def handle_file_shared_events(
    ack: Ack, client: WebClient, event: dict[str, Any] | None, logger: logging.Logger
) -> None:
    logger.info(event)

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
            # TODO: add a fail/sad emoji reaction
            return

        # TODO: handle error when downloading the file
        # download the file with a stream via httpx
        file_path = f"/tmp/{file.id}.{file.filetype}"

        # TODO: use stream to avoid loading the whole file in memory
        with open(file_path, "wb") as f:
            res = httpx.get(
                file.url_private,
                # TODO: how to get the token with oauth?
                headers={"Authorization": f"Bearer {SLACK_BOT_TOKEN}"},
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
            # TODO: use a schema to validate the response, such as pydantic
            try:
                result = FuzzyOctoDiscoResponse.parse_obj(res.json())
            except ValidationError as error:
                logger.error(f"Failed to parse fuzzy-octo-disco response: {error}")
                raise error

            if result.status == "SUCCESS":
                logger.debug(
                    f"Found {result.nbFaces} faces. Sending on channel {e.channel} and thread {e.event_ts}"
                )
                # TODO use an emoji reaction instead
                client.chat_postMessage(
                    text=f"Found {result.nbFaces}",
                    channel=e.channel,
                    thread_ts=e.event_ts,
                )
                # TODO: send photos as an album
                for i in range(int(result.nbFaces)):
                    result_path = result.paths[i]
                    try:
                        pass
                        client.files_upload_v2(
                            file=result_path,
                            channel=e.channel,
                            thread_ts=e.event_ts,
                        )
                    except Exception as error:
                        logger.warning(f"Failed to send face {i}: {error}")
                        pass
                    finally:
                        try:
                            # Remove the file
                            Path(result.paths[i]).remove_p()
                        except Exception as error:
                            logger.warning(f"Failed to remove face {i}: {error}")
                            pass

            elif result.status in ("NO_FACE_FOUND", "FAILED_ALL_FACES"):
                logger.info("No faces found")
                # TODO: add a fail/sad emoji reaction
            else:
                # TODO: add a fail emoji reaction
                logger.error(
                    f"Received {result.status} from fuzzy-octo-disco: {result.message}"
                )
        except httpx.RequestError as exc:
            logger.error(
                f"An error occurred while requesting {exc.request.url!r}: {exc}"
            )
            # TODO: add a fail emoji reaction
        finally:
            # TODO: remove the file
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
