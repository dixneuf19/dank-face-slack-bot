from pydantic import BaseModel


class File(BaseModel):
    id: str
    filetype: str
    url_private: str


class Event(BaseModel):
    channel: str
    files: list[File]
    event_ts: str


class FuzzyOctoDiscoResponse(BaseModel):
    status: str
    nbFaces: int = 0
    paths: list[str] = []
    message: str = ""
