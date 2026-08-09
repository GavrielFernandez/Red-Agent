"""Async reflected-XSS confirmation using a headless browser.

This module is intentionally designed for authorized validation only.
It verifies actual JavaScript execution by watching console and dialog events
instead of relying on text reflection alone.

Optional dependency:
- playwright

If Playwright is missing, the validator returns an unavailable result
instead of failing the orchestration pipeline.
"""

from __future__ import annotations

import asyncio
import html
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from .models import ValidationAttempt, ValidationResult


DEFAULT_MARKER = "RedAgent_XSS_Confirmed"
DEFAULT_PAYLOAD = (
    "\"><svg onload=\"console.log('RedAgent_XSS_Confirmed');"
    "window.__redagent_xss_confirmed=true\"></svg>"
)


@dataclass
class XSSObservation:
    """Collected browser observations while validating a payload."""

    console_messages: List[str]
    dialogs: List[str]
    page_errors: List[str]
    reflected: bool
    executed: bool
    status_code: Optional[int] = None
    final_url: str = ""
    response_title: str = ""
    response_body_excerpt: str = ""


class ActiveXSSValidator:
    """Confirm whether a reflected XSS marker actually executes in a browser."""

    def __init__(
        self,
        *,
        headless: bool = True,
        navigation_timeout_ms: int = 25000,
        post_load_wait_ms: int = 2000,
        browser_channel: Optional[str] = None,
    ):
        self.headless = headless
        self.navigation_timeout_ms = navigation_timeout_ms
        self.post_load_wait_ms = post_load_wait_ms
        self.browser_channel = browser_channel

    def _build_test_url(
        self,
        url: str,
        payload: str,
        parameter_name: str = "q",
    ) -> str:
        parsed = urlparse(url)
        query_items = dict(parse_qsl(parsed.query, keep_blank_values=True))
        query_items[parameter_name] = payload
        new_query = urlencode(query_items, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    async def validate(
        self,
        url: str,
        *,
        parameter_name: str = "q",
        payload: Optional[str] = None,
        marker: str = DEFAULT_MARKER,
    ) -> ValidationResult:
        """Validate reflected XSS by executing a benign browser-side payload."""

        payload = payload or DEFAULT_PAYLOAD
        test_url = self._build_test_url(url, payload, parameter_name=parameter_name)

        attempt = ValidationAttempt(
            tool="active_xss_validator",
            target=test_url,
            ok=False,
            status="unavailable",
            message="Playwright is not installed",
            evidence={"payload": payload, "marker": marker},
        )

        try:
            from playwright.async_api import async_playwright  # type: ignore
        except Exception as exc:
            return ValidationResult(
                validator="active_xss_validator",
                target=url,
                finding_type="xss",
                confirmed=False,
                status="unavailable",
                confidence=0.0,
                message="Playwright is required for browser-based XSS validation",
                evidence={"error": str(exc), "payload": payload, "marker": marker},
                attempts=[attempt],
                errors=["Missing playwright dependency"],
            )

        console_messages: List[str] = []
        dialogs: List[str] = []
        page_errors: List[str] = []
        response_title = ""
        response_body_excerpt = ""
        final_url = test_url
        status_code: Optional[int] = None

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=self.headless,
                    channel=self.browser_channel,
                )
                context = await browser.new_context(ignore_https_errors=True)
                page = await context.new_page()

                async def on_console(msg):
                    try:
                        console_messages.append(msg.text)
                    except Exception:
                        console_messages.append(str(msg))

                async def on_dialog(dialog):
                    dialogs.append(f"{dialog.type}:{dialog.message}")
                    await dialog.dismiss()

                async def on_page_error(error):
                    page_errors.append(str(error))

                page.on("console", lambda msg: asyncio.create_task(on_console(msg)))
                page.on("dialog", lambda dialog: asyncio.create_task(on_dialog(dialog)))
                page.on("pageerror", lambda error: asyncio.create_task(on_page_error(error)))

                response = await page.goto(
                    test_url,
                    wait_until="domcontentloaded",
                    timeout=self.navigation_timeout_ms,
                )
                if response is not None:
                    status_code = response.status

                # Allow delayed execution handlers, SPA hydration, etc.
                await page.wait_for_timeout(self.post_load_wait_ms)

                try:
                    reflected = marker in (await page.content())
                except Exception:
                    reflected = False

                try:
                    response_title = await page.title()
                except Exception:
                    response_title = ""

                try:
                    body_text = await page.locator("body").inner_text(timeout=3000)
                    response_body_excerpt = body_text[:600]
                except Exception:
                    response_body_excerpt = ""

                executed = False
                try:
                    executed = bool(await page.evaluate("Boolean(window.__redagent_xss_confirmed)"))
                except Exception:
                    executed = False

                console_hit = any(marker in msg for msg in console_messages)
                dialog_hit = any(marker in msg for msg in dialogs)
                executed = executed or console_hit or dialog_hit
                final_url = page.url

                await context.close()
                await browser.close()

        except Exception as exc:
            return ValidationResult(
                validator="active_xss_validator",
                target=url,
                finding_type="xss",
                confirmed=False,
                status="error",
                confidence=0.0,
                message=str(exc),
                evidence={
                    "payload": payload,
                    "marker": marker,
                    "test_url": test_url,
                    "console_messages": console_messages,
                    "dialogs": dialogs,
                    "page_errors": page_errors,
                },
                attempts=[ValidationAttempt(
                    tool="active_xss_validator",
                    target=test_url,
                    ok=False,
                    status="error",
                    message=str(exc),
                    evidence={"payload": payload, "marker": marker},
                )],
                errors=[str(exc)],
            )

        confidence = 0.95 if executed else 0.25 if reflected else 0.0
        status = "confirmed" if executed else "reflected_only" if reflected else "not_confirmed"
        message = (
            "JavaScript executed in browser" if executed else
            "Payload reflected but no JavaScript execution observed" if reflected else
            "No reflection or execution observed"
        )

        evidence = {
            "payload": payload,
            "marker": marker,
            "test_url": test_url,
            "final_url": final_url,
            "status_code": status_code,
            "console_messages": console_messages,
            "dialogs": dialogs,
            "page_errors": page_errors,
            "reflected": reflected,
            "executed": executed,
            "title": response_title,
            "body_excerpt": html.escape(response_body_excerpt),
        }

        return ValidationResult(
            validator="active_xss_validator",
            target=url,
            finding_type="xss",
            confirmed=executed,
            status=status,
            confidence=confidence,
            message=message,
            evidence=evidence,
            attempts=[ValidationAttempt(
                tool="active_xss_validator",
                target=test_url,
                ok=executed,
                status=status,
                message=message,
                evidence=evidence,
            )],
        )
