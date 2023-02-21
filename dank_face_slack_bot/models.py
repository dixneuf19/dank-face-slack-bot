from pydantic import BaseModel


class File(BaseModel):
    id: str
    filetype: str
    url_private: str


class Event(BaseModel):
    channel: str
    files: list[File]
    event_ts: str
