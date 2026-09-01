from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any

from sqlalchemy.orm import Session

from ai.llm_client import LLMClient
from database.models import PipelineStepRun, PipelineStepStatus, ProjectStage
from utils import now_utc

logger = logging.getLogger(__name__)


class BaseSecurityStep(ABC):
    """
    Every step in the deterministic security analysis pipeline (System
    Analysis, Asset Discovery, Threat Modeling, ...) subclasses this. It is
    NOT an autonomous agent — it does not decide what to do next, does not
    call other steps, and holds no state beyond one call. The Python
    pipeline function (pipeline/security_analysis_pipeline.py) is solely
    responsible for deciding which step runs when and in what order.

    This base class standardizes two things every step needs:
      - calling the LLM (via the shared, provider-agnostic LLMClient)
      - recording a PipelineStepRun row — this is what the Security
        Analysis Pipeline page and Pipeline Activity Log read from, so
        those UI features reflect real execution history, not simulated
        progress.
    """

    name: str = "Security Step"
    stage: ProjectStage = ProjectStage.SYSTEM_ANALYSIS

    def __init__(self, db: Session, llm: LLMClient | None = None):
        self.db = db
        self.llm = llm or LLMClient()

    @abstractmethod
    def run(self, project_id: str, context: dict[str, Any]) -> dict[str, Any]:
        """Execute this step's task and return a structured output dict."""

    def _start_run(self, project_id: str, input_summary: dict) -> PipelineStepRun:
        run = PipelineStepRun(
            project_id=project_id,
            step_name=self.name,
            stage=self.stage,
            status=PipelineStepStatus.RUNNING,
            input_summary=input_summary,
            started_at=now_utc(),
        )
        self.db.add(run)
        self.db.commit()
        self.db.refresh(run)
        return run

    def _finish_run(self, run: PipelineStepRun, *, output_summary: dict, reasoning_summary: str = "",
                     status: PipelineStepStatus = PipelineStepStatus.SUCCEEDED, error: str | None = None):
        run.status = status
        run.output_summary = output_summary
        run.reasoning_summary = reasoning_summary
        run.error = error
        run.finished_at = now_utc()
        self.db.add(run)
        self.db.commit()

    def execute_with_logging(self, project_id: str, context: dict[str, Any]) -> dict[str, Any]:
        run = self._start_run(project_id, {"keys": list(context.keys())})
        try:
            result = self.run(project_id, context)
            self._finish_run(
                run,
                output_summary=result.get("_summary", {}),
                reasoning_summary=result.get("_reasoning", ""),
            )
            return result
        except Exception as exc:  # noqa: BLE001
            logger.exception("%s failed for project %s", self.name, project_id)
            self._finish_run(run, output_summary={}, status=PipelineStepStatus.FAILED, error=str(exc))
            raise
