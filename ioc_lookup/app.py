# -*- coding: utf-8 -*-

import sys
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from os import environ
from typing import Any, List, Optional

import slack
import yaml
from flask import Response, abort, current_app, jsonify, redirect, render_template, request, url_for
from flask_accept import accept_fallback
from flask_caching import Cache
from flask_limiter import Limiter
from pymisp import PyMISPError
from werkzeug.middleware.proxy_fix import ProxyFix
from whitenoise import WhiteNoise

from ioc_lookup.ioc_lookup_app import IOCLookupApp, TrustedOrg
from ioc_lookup.log import init_logging
from ioc_lookup.misp_api import TLP, AttrType, MISPApi, RequestException
from ioc_lookup.misp_attributes import SUPPORTED_TYPES, Attr
from ioc_lookup.utils import (
    EventInfoException,
    ParseException,
    ReportData,
    SightingsData,
    TagParseException,
    User,
    get_ipaddr_or_eppn,
    get_sightings_data,
    get_user,
    misp_api_for,
    parse_item,
    request_to_data,
    utc_now,
)

# Read config
config_path = environ.get("IOC_LOOKUP_CONFIG", "config.yaml")
try:
    with open(config_path) as f:
        config = yaml.safe_load(f)
except FileNotFoundError as e:
    print("Set environment variable IOC_LOOKUP_CONFIG to config file path")
    print(e)
    sys.exit(1)


# Init app
app = IOCLookupApp(__name__)
app.config.from_mapping(config)
# Init logging
app.config.setdefault("LOG_LEVEL", "INFO")
app.config.setdefault("LOG_COLORIZE", False)
init_logging(level=app.config["LOG_LEVEL"], colorize=app.config["LOG_COLORIZE"])
# Init static files
app.wsgi_app = WhiteNoise(app.wsgi_app, root=config.get("STATIC_FILES", "ioc_lookup/static/"))  # type: ignore
# Init trusted user list
if app.config.get("TRUSTED_USERS"):
    try:
        with open(app.config["TRUSTED_USERS"]) as f:
            loaded_yaml = yaml.safe_load(f)
            app.trusted_users = loaded_yaml["eppn"]
            app.api_keys = loaded_yaml["api_keys"]
        app.logger.info("Loaded trusted user list and api keys")
        app.logger.debug(f"Trusted user list: {app.trusted_users}")
        app.logger.debug(f"Trusted user with api keys: {app.api_keys.values()}")
    except IOError as e:
        app.logger.warning(f"Could not initialize trusted user list: {e}")

# Init trusted orgs
if app.config.get("TRUSTED_ORGS"):
    try:
        with open(app.config["TRUSTED_ORGS"]) as f:
            trusted_orgs = yaml.safe_load(f)
        for key, value in trusted_orgs["org_domains"].items():
            app.trusted_orgs[key.lower()] = TrustedOrg(domain=key, misp_api_key=value)
        app.logger.info("Loaded trusted org list")
        app.logger.debug(f"Trusted org config: {app.trusted_orgs}")
    except (IOError, KeyError) as e:
        app.logger.warning(f"Could not initialize trusted org mapping: {e}")

# Init other settings
app.config.setdefault("SIGHTINGS_ENABLED", True)
app.config.setdefault("SIGHTING_SOURCE_PREFIX", "flask-ioc-lookup_")
app.config.setdefault("SIGHTING_MIN_POSITIVE_VOTE_HOURS", 24)
app.config.setdefault("ALLOWED_EVENT_TAGS", [])
app.jinja_options["autoescape"] = lambda _: True  # autoescape all templates

# Init MISP APIs
try:
    app.misp_apis = {
        "default": MISPApi(
            name="default",
            api_url=app.config["MISP_URL"],
            api_key=app.config["MISP_KEY"],
            verify_cert=app.config["MISP_VERIFYCERT"],
        )
    }
    # Set proxy api to default if not explicitly set in config trusted orgs
    if "proxy" not in app.trusted_orgs:
        app.logger.info("proxy not set in trusted orgs config, using default as proxy org")
        app.misp_apis["proxy"] = app.misp_apis["default"]
except PyMISPError as e:
    app.logger.error(e)
    app.misp_apis = None

# Init Slack
slackclient = slack.WebClient(token=app.config["SLACK_TOKEN"])
try:
    SLACK_ID = slackclient.api_call("auth.test").get("user_id")  # type: ignore
    app.logger.debug(f"Initialized slack webclient")
except Exception:
    SLACK_ID = None
    app.logger.error(f"Could not initialize slack webclient")

# Init rate limiting
limiter = Limiter(app=app, key_func=get_ipaddr_or_eppn)

# Init cache
cache = Cache(app)

# Proxyfix
app.wsgi_app = ProxyFix(app.wsgi_app)  # type: ignore[method-assign]


def rate_limit_from_config() -> str:
    return app.config.get("REQUEST_RATE_LIMIT", "1/second")


@app.template_filter("ts")
def _jinja2_filter_ts(ts: str) -> str:
    dt = datetime.fromtimestamp(int(ts), tz=timezone.utc)
    fmt = "%Y-%m-%d %H:%M:%S"
    return dt.strftime(fmt)


@app.errorhandler(PyMISPError)
def misp_unavailable(exception: Exception):
    app.logger.error(exception)
    if "application/json" in request.accept_mimetypes.values():
        return (
            jsonify(
                {
                    "status": 500,
                    "message": "MISP not available",
                    "details": "MISP server is not available at the moment. Please try again later.",
                }
            ),
            500,
        )
    return render_template("unavailable.jinja2")


@app.errorhandler(RequestException)
def misp_request_error(exception: Exception):
    app.logger.error(exception)
    if "application/json" in request.accept_mimetypes.values():
        return jsonify({"status": 500, "message": "MISP request error", "details": str(exception)}), 500
    return render_template("misp_request_error.jinja2", message=str(exception))


@app.errorhandler(401)
def custom_401(error: Exception):
    if "application/json" in request.accept_mimetypes.values():
        return jsonify({"status": 401, "message": "Unauthorized"}), 401
    return Response("401 Unauthorized", 401)


@dataclass
class SearchResult:
    result: List[Any]
    sightings_data: SightingsData
    related_result: List[Any]


@dataclass
class SearchContext:
    user: User
    misp_url: str
    supported_types: list[str]
    supported_tags: list[str]
    parsed_search_query: Optional[Attr] = None
    parent_domain_name: Optional[str] = None
    related_results: bool = False
    related_results_limit: Optional[int] = None
    error: Optional[str] = None
    tlp: dict[str, str] = field(default_factory=TLP.to_dict)


@cache.memoize()
def do_search(
    search_item: Attr,
    user: User,
    limit_days: Optional[int] = None,
    related_results: Optional[bool] = None,
    limit_related: Optional[int] = None,
):
    related_result = []
    with misp_api_for() as api:  # Use the default api to get non org specific data
        result = api.attr_search(search_item)
        if AttrType.DOMAIN in search_item.search_types or AttrType.URL in search_item.search_types:
            first_level_domain = search_item.get_first_level_domain()
            # Only add to the search if first_level_domain differs from search_item
            if first_level_domain and related_results is True:
                # return events after this date, None for all
                publish_timestamp = None
                if limit_days is not None:
                    publish_timestamp = utc_now() - timedelta(days=limit_days)

                related_result = api.domain_name_search(
                    domain_name=f"%.{first_level_domain}%",
                    searchall=True,
                    publish_timestamp=publish_timestamp,
                    limit=limit_related,
                )

    # allow disabling of sightings
    sightings_data = SightingsData(can_add_sighting=False, can_add_false_positive=False, votes={})
    if current_app.config["SIGHTINGS_ENABLED"]:
        sightings_data = get_sightings_data(user=user, search_result=result)
    return SearchResult(result=result, related_result=related_result, sightings_data=sightings_data)


def do_add_event(user: User, report_data: ReportData, extra_tags: list[str] | None = None) -> ReportData:
    if user.is_trusted_user:
        report_data.publish = True

    report_user = user
    if report_data.by_proxy is True:
        # replace identifying parts when reporting through proxy
        report_user = User(
            identifier="proxy",
            is_trusted_user=user.is_trusted_user,
            in_trusted_org=user.in_trusted_org,
            org_domain="proxy",
        )
        current_app.logger.info(f"Reporting event by proxy for user {user}")

    if extra_tags is not None:
        report_data.tags.extend(extra_tags)

    with misp_api_for(report_user) as api:
        if report_data.items:
            ret = api.add_event(
                attr_items=report_data.items,
                info=report_data.info,
                tags=report_data.tags,
                comment=f"Reported by {report_user.identifier}",
                to_ids=True,
                distribution=api.tlp_to_distribution(report_data.tlp),
                reference=report_data.reference,
                published=report_data.publish,
            )
            current_app.logger.debug(f"add_event ret: {ret}")
    return report_data


# Views
@app.route("/", defaults={"search_query": None}, methods=["GET", "POST"])
@app.route("/<search_query>", methods=["GET", "POST"])
@accept_fallback
@limiter.limit(rate_limit_from_config)
def index(search_query: str | None = None):
    user = get_user()
    search_context = SearchContext(
        user=user,
        misp_url=current_app.config["MISP_URL"],
        supported_types=SUPPORTED_TYPES,
        supported_tags=app.config["ALLOWED_EVENT_TAGS"],
    )

    if app.misp_apis is None:
        raise PyMISPError("No MISP session exists")

    if request.method == "POST" or search_query is not None:
        original_search_query: str | None = request.form.get("search_query")
        if not original_search_query:
            original_search_query = search_query

        search_context.parsed_search_query = parse_item(original_search_query)
        if search_context.parsed_search_query:
            # toggle search for related results
            wants_related_results = request.form.get("related_results") or request.args.get("related_results") or "no"
            if wants_related_results == "yes":
                search_context.related_results = True
            # limit number of results, None for all
            if request.form.get("limit_related_results") != "no":
                # set limit for related result
                search_context.related_results_limit = app.config.get("LIMIT_RELATED_RESULTS", None)
            limit_days = app.config.get("LIMIT_DAYS_RELATED_RESULTS")
            search_result = do_search(
                search_item=search_context.parsed_search_query,
                user=user,
                limit_days=limit_days,
                related_results=search_context.related_results,
                limit_related=search_context.related_results_limit,
            )

            return render_template(
                "index.jinja2",
                search_result=search_result,
                search_context=search_context,
                sightings_enabled=current_app.config["SIGHTINGS_ENABLED"],
            )

        search_context.error = "Invalid input"

    return render_template("index.jinja2", search_context=search_context)


@index.support("application/json")
def index_json(search_query: Optional[str] = None):
    user = get_user()
    search_context = SearchContext(
        user=user,
        misp_url=current_app.config["MISP_URL"],
        supported_types=SUPPORTED_TYPES,
        supported_tags=app.config["ALLOWED_EVENT_TAGS"],
    )

    if app.misp_apis is None:
        raise PyMISPError("No MISP session exists")

    if request.method == "POST" and search_query is None:
        if request.json is not None:
            search_query = request.json.get("search")

    app.logger.debug(f"Search query: {search_query}")
    if search_query is not None:
        original_search_query = request.form.get("search")
        if not original_search_query:
            original_search_query = search_query

        search_context.parsed_search_query = parse_item(original_search_query)
        if search_context.parsed_search_query is None:
            return jsonify({"error": "Invalid input"})

        try:
            search_result = do_search(search_item=search_context.parsed_search_query, user=user)
        except Exception as e:
            return jsonify({"error": str(e)})
        return jsonify({"result": search_result.result})
    return jsonify({"error": "No search query"})


@app.route("/slack/ioc-lookup", methods=["POST"])
@limiter.limit(rate_limit_from_config)
def slacksearch():
    user = get_user()  # form.get('user_name')
    form = request.form
    channel_id = form.get("channel_id")
    search_query = form.get("text")
    search_context = SearchContext(user=user, misp_url=current_app.config["MISP_URL"], supported_types=SUPPORTED_TYPES)

    if app.misp_apis is None:
        slackclient.chat_postMessage(channel=channel_id, text=f"No MISP session exists")
        return Response(), 200

    original_search_query = search_query

    search_context.parsed_search_query = parse_item(original_search_query)
    if search_context.parsed_search_query:
        limit_days = app.config.get("LIMIT_DAYS_RELATED_RESULTS")
        search_result = do_search(search_item=search_context.parsed_search_query, user=user, limit_days=limit_days)

        for item in search_result.result:
            slackclient.chat_postMessage(
                channel=channel_id, text=f"{search_context.misp_url}events/view/{item['event_id']}"
            )
        return Response(), 200
    else:
        search_context.error = "Invalid input"
        slackclient.chat_postMessage(channel=channel_id, text=f"{search_context.error}: {search_query}")
        return Response(), 200


@app.route("/report", methods=["GET", "POST"])
@accept_fallback
@limiter.limit(rate_limit_from_config)
def report():
    user = get_user()
    default_args = {
        "supported_types": SUPPORTED_TYPES,
        "supported_tags": app.config["ALLOWED_EVENT_TAGS"],
        "tlp": TLP.to_dict(),
        "user": user,
    }

    if app.misp_apis is None:
        raise PyMISPError("No MISP session exists")

    if request.method == "POST":
        try:
            data = request_to_data()
            report_data = ReportData.load_data(data=data)
        except TagParseException as ex:
            app.logger.error(ex)
            return render_template("report.jinja2", error={"tags": "Invalid tag input"}, **default_args)
        except EventInfoException as ex:
            app.logger.error(ex)
            return render_template(
                "report.jinja2", error={"info": "Event info needs to be a short description"}, **default_args
            )
        except (ValueError, ParseException) as ex:
            app.logger.error(ex)
            return render_template("report.jinja2", error={"entities": "Could not parse entities"}, **default_args)

        if report_data is None:
            return render_template("report.jinja2", error={"form": "No valid input found"}, **default_args)

        report_data = do_add_event(user=user, report_data=report_data, extra_tags=["reported_by:person"])

        result = "success"
        return render_template("report.jinja2", result=result, reported_items=report_data.items, **default_args)
    return render_template("report.jinja2", **default_args)


@report.support("application/json")
def report_json():

    user = get_user()

    if app.misp_apis is None:
        raise PyMISPError("No MISP session exists")

    if request.method != "POST":
        return jsonify({"error": "Invalid request method"})
    try:
        data = request_to_data()
        report_data = ReportData.load_data(data=data)
    except TagParseException as ex:
        app.logger.error(ex)
        supported_tags = app.config["ALLOWED_EVENT_TAGS"]
        return jsonify({"error": "Invalid tag input", "supported_tags": supported_tags})
    except EventInfoException as ex:
        app.logger.error(ex)
        return jsonify({"error": "Event info needs to be a short description"})
    except (ValueError, ParseException) as ex:
        app.logger.error(ex)
        return jsonify({"error": "Invalid input", "supported_types": SUPPORTED_TYPES})

    if report_data is None:
        return jsonify({"error": "No valid input found"})

    try:
        report_data = do_add_event(user=user, report_data=report_data, extra_tags=["reported_by:api"])
    except Exception as e:
        return jsonify({"error": str(e)})

    report_items = [{"type": item.type.value, "value": item.value} for item in report_data.items]
    return jsonify({"report": report_items})


@app.route("/report-sighting", methods=["POST"])
@limiter.limit(rate_limit_from_config)
def report_sighting():
    if current_app.config["SIGHTINGS_ENABLED"] is False:
        return abort(401)

    user = get_user()

    if not user.in_trusted_org:
        return abort(401)

    sighting_in = parse_item(request.form.get("search_query", ""))
    type_in = request.form.get("type", "")
    if not sighting_in or not type_in:
        abort(400)

    with misp_api_for() as api:
        result = api.attr_search(sighting_in)

    sightings_data = get_sightings_data(user=user, search_result=result)
    if (sightings_data.can_add_sighting and type_in == "0") or (
        sightings_data.can_add_false_positive and type_in == "1"
    ):
        app.logger.debug(f"report-sighting: {[item.value for item in sighting_in.search_types]} {sighting_in.value}")
        app.logger.debug(f"report-sighting: type {type_in}")
        with misp_api_for(user) as api:
            api.add_sighting(
                attr=sighting_in,
                sighting_type=type_in,
                source=f'{app.config["SIGHTING_SOURCE_PREFIX"]}{user.org_domain}',
            )
    return redirect(url_for("index", search_query=urllib.parse.quote_plus(sighting_in.value)))


@app.route("/remove-sighting", methods=["POST"])
@limiter.limit(rate_limit_from_config)
def remove_sighting():
    if current_app.config["SIGHTINGS_ENABLED"] is False:
        return abort(401)

    user = get_user()
    if not user.in_trusted_org:
        return abort(401)

    sighting_in = parse_item(request.form.get("search_query", ""))
    type_in = request.form.get("type", "")
    if not sighting_in or not type_in:
        abort(400)

    date_from = None
    date_to = None

    if type_in == "0":
        # Only remove sightings added in the last X hours
        min_vote_hours = current_app.config["SIGHTING_MIN_POSITIVE_VOTE_HOURS"]
        date_to = datetime.utcnow()
        date_from = date_to - timedelta(hours=min_vote_hours)

    app.logger.debug(f"remove-sighting: {[item.value for item in sighting_in.search_types]} {sighting_in.value}")
    app.logger.debug(f"remove-sighting: type {type_in}")
    app.logger.debug(f"remove-sighting: date_from {date_from}")
    app.logger.debug(f"remove-sighting: date_to {date_to}")

    with misp_api_for(user) as api:
        api.remove_sighting(
            attr=sighting_in,
            sighting_type=type_in,
            date_from=date_from,
            date_to=date_to,
            source=f'{app.config["SIGHTING_SOURCE_PREFIX"]}{user.org_domain}',
        )

    return redirect(url_for("index", search_query=urllib.parse.quote_plus(sighting_in.value)))


if __name__ == "__main__":
    app.run()
