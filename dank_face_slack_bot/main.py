import logging
import os

import httpx
from fastapi import FastAPI, Request
from path import Path
from slack_bolt import App
from slack_bolt.adapter.fastapi import SlackRequestHandler

# from slack_bolt.oauth.oauth_settings import OAuthSettings
# from slack_sdk.oauth.installation_store import FileInstallationStore
# from slack_sdk.oauth.state_store import FileOAuthStateStore

FUZZY_OCTO_DISCO_ADDRESS = f'{os.getenv("FUZZY_OCTO_DISCO_HOST", default="http://localhost")}:{os.getenv("FUZZY_OCTO_DISCO_PORT", default="8080")}'
FUZZY_OCTO_DISCO_TIMEOUT_SECONDS = int(
    os.getenv("FUZZY_OCTO_DISCO_TIMEOUT_SECONDS", default="60")
)
SLACK_BOT_TOKEN = os.environ.get("SLACK_BOT_TOKEN")


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
logging.basicConfig(level=logging.DEBUG)


# @app.event("file_shared")
@app.event({"type": "message", "subtype": "file_share"})
def handle_file_shared_events(ack, client, event, logger):
    logger.info(event)
    ack()
    for file in event.get("files"):
        if file.get("filetype") not in ("jpg", "png", "webm", "gif"):
            logger.info("File is not an image")
            # TODO: add a fail/sad emoji reaction
            return

        # download the file with a stream via httpx
        file_path = f"/tmp/{file.get('id')}.{file.get('filetype')}"
        file_path = "/tmp/test.png"
        with open(file_path, "wb") as f:
            res = httpx.get(
                file.get("url_private"),
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
            result = res.json()
            if result.get("status") == "SUCCESS":
                logger.info(
                    f"Found {result.get('nbFaces')} faces sening on channel {event.get('channel')} and thread {event.get('event_ts')}"
                )
                client.chat_postMessage(
                    text=f"Found {result.get('nbFaces')}",
                    channel=event.get("channel"),
                    thread_ts=event.get("event_ts"),
                )
                for i in range(int(result.get("nbFaces"))):
                    result_path = result.get("paths")[i]
                    try:
                        pass
                        client.files_upload_v2(
                            file=result_path,
                            channel=event.get("channel"),
                            thread_ts=event.get("event_ts"),
                        )
                    except Exception as error:
                        logger.warning(f"Failed to send face {i}: {error}")
                        pass
                    finally:
                        try:
                            # Remove the file
                            Path(result["paths"][i]).remove_p()
                        except Exception as error:
                            logger.warning(f"Failed to remove face {i}: {error}")
                            pass

            elif result["status"] in ("NO_FACE_FOUND", "FAILED_ALL_FACES"):
                logger.info("No faces found")
                # TODO: add a fail/sad emoji reaction
            else:
                logger.error(
                    f"Received {result['status']} from fuzzy-octo-disco: {result['message']}"
                )
        except httpx.RequestError as exc:
            logger.error(
                f"An error occurred while requesting {exc.request.url!r}: {exc}"
            )
        finally:
            # TODO: remove the file
            pass


# @app.event("message")
# def handle_message_events(event, body, logger):
#     logger.info(event)
#     logger.info(body)


api = FastAPI()


@api.post("/slack/events")
async def endpoint(req: Request):
    return await app_handler.handle(req)


@api.get("/slack/install")
async def install(req: Request):
    return await app_handler.handle(req)


@api.get("/slack/oauth_redirect")
async def oauth_redirect(req: Request):
    return await app_handler.handle(req)


@api.get("/health")
async def get_health():
    return {"message": "OK"}
