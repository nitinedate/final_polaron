from pydantic import BaseModel


class JobCreate(BaseModel):
    type: str = "host_disk"
    domain_pack: str | None = "forensic"
    case_id: str | None = None
    mobile_os: str | None = None
    source_type: str | None = None
    acquisition_mode: str | None = None
    legal_authority_acknowledged: bool = False
    evidence_path: str | None = None


class IngestPathBody(BaseModel):
    path: str | None = None
    source_type: str = "disk"
    selected_names: list[str] | None = None
    auto_process: bool = False
    drive: str = ""
    browse_path: str = ""
    # When true, skip folder listing (client already called list-folder).
    skip_folder_list: bool = False
    # standard | deep.  None = keep the profile already stored on the job (set by
    # PUT /jobs/{id}/processing-profile when the examiner picks the mode); a
    # default here used to overwrite a stored "deep" choice with "standard".
    processing_profile: str | None = None


class ProcessingProfileBody(BaseModel):
    processing_profile: str  # standard | deep


class ListFolderBody(BaseModel):
    path: str | None = None
    drive: str = ""
    browse_path: str = ""


class ResolveFolderBody(BaseModel):
    filenames: list[str] | None = None
    files: list[str] | None = None
    folder_hint: str | None = None
    folder: str | None = None
    relative_path: str | None = None
    relative_paths: list[str] | None = None
    paths: list[str] | None = None
    # Optional exact byte sizes keyed by filename. Browser-selected E01 sets use
    # this to prove a server-drive match before deciding whether any upload is
    # necessary. Filename-only matches are unsafe across forensic cases.
    file_sizes: dict[str, int] | None = None
