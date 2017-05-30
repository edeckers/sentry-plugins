from __future__ import absolute_import

import dateutil.parser
import hashlib
import hmac
import logging
import six
import re

from django.db import IntegrityError, transaction
from django.http import HttpResponse, Http404
from django.utils.crypto import constant_time_compare
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import View
from django.utils import timezone
from simplejson import JSONDecodeError
from sentry.models import (
    Commit, CommitAuthor, Organization, OrganizationOption,
    Repository
)
from sentry.plugins.providers import RepositoryProvider
from sentry.utils import json

# from sentry_plugins.exceptions import ApiError
# from sentry_plugins.bitbucket.client import BitbucketClient

logger = logging.getLogger('sentry.webhooks')


def is_anonymous_email(email):
    # todo(maxbittker)
    return email[-25:] == '@users.noreply.bitbucket.com'


def get_external_id(username):
    # todo(maxbittker)
    return 'bitbucket:%s' % username


class Webhook(object):
    def __call__(self, organization, event):
        raise NotImplementedError


def parse_raw_user(raw):
    # captures content between angle brackets
    return re.search('(?<=<).*(?=>$)', raw).group(0)


class PushEventWebhook(Webhook):
    # https://confluence.atlassian.com/bitbucket/event-payloads-740262817.html#EventPayloads-Push
    def __call__(self, organization, event):
        authors = {}

        # client = BitbucketClient()
        try:
            repo = Repository.objects.get(
                organization_id=organization.id,
                provider='bitbucket',
                external_id=six.text_type(event['repository']['uuid']),
            )
        except Repository.DoesNotExist:
            raise Http404()

        for change in event['push']['changes']:
            for commit in change['commits']:
                if RepositoryProvider.should_ignore_commit(commit['message']):
                    continue

                author_email = parse_raw_user(commit['author']['raw'])
                if '@' not in author_email:
                    author_email = u'{}@localhost'.format(author_email[:65])

                # TODO(dcramer): we need to deal with bad values here, but since
                # its optional, lets just throw it out for now
                if len(author_email) > 75:
                    author = None
                elif author_email not in authors:
                    authors[author_email] = author = CommitAuthor.objects.get_or_create(
                        organization_id=organization.id,
                        email=author_email,
                        defaults={
                            'name': commit['author']['user']['display_name'][:128],
                        }
                    )[0]
                else:
                    author = authors['author_email']
                try:
                    with transaction.atomic():

                        Commit.objects.create(
                            repository_id=repo.id,
                            organization_id=organization.id,
                            key=commit['hash'],
                            message=commit['message'],
                            author=author,
                            date_added=dateutil.parser.parse(
                                commit['date'],
                            ).astimezone(timezone.utc),
                        )

                        # TODO(maxbittker) can't make these work until i save the auth token somewhere
                        #
                        # patch_set  = client.get_commit_filechanges(repo, commit['hash'])
                        #
                        # for patched_file in patch_set.added_files:
                        #     CommitFileChange.objects.create(
                        #         organization_id=organization.id,
                        #         commit=c,
                        #         filename=patched_file.path,
                        #         type='A',
                        #     )
                        # for patched_file in patch_set.removed_files:
                        #     CommitFileChange.objects.create(
                        #         organization_id=organization.id,
                        #         commit=c,
                        #         filename=patched_file.path,
                        #         type='D',
                        #     )
                        # for patched_file in path_set.modified_files:
                        #     CommitFileChange.objects.create(
                        #         organization_id=organization.id,
                        #         commit=c,
                        #         filename=patched_file.path,
                        #         type='M',
                        #     )
                except IntegrityError:
                    pass


class BitbucketWebhookEndpoint(View):
    _handlers = {
        'repo:push': PushEventWebhook,
    }

    # https://developer.github.com/webhooks/
    def get_handler(self, event_type):
        return self._handlers.get(event_type)

    def is_valid_signature(self, method, body, secret, signature):
        if method == 'sha1':
            mod = hashlib.sha1
        else:
            raise NotImplementedError('signature method %s is not supported' % (
                method,
            ))
        expected = hmac.new(
            key=secret.encode('utf-8'),
            msg=body,
            digestmod=mod,
        ).hexdigest()
        return constant_time_compare(expected, signature)

    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        if request.method != 'POST':
            return HttpResponse(status=405)

        return super(BitbucketWebhookEndpoint, self).dispatch(request, *args, **kwargs)

    def post(self, request, organization_id):
        try:
            organization = Organization.objects.get_from_cache(
                id=organization_id,
            )
        except Organization.DoesNotExist:
            logger.error('bitbucket.webhook.invalid-organization', extra={
                'organization_id': organization_id,
            })
            return HttpResponse(status=400)

        secret = OrganizationOption.objects.get_value(
            organization=organization,
            key='bitbucket:webhook_secret',
        )
        if secret is None:
            logger.error('bitbucket.webhook.missing-secret', extra={
                'organization_id': organization.id,
            })
            return HttpResponse(status=401)

        body = six.binary_type(request.body)
        if not body:
            logger.error('bitbucket.webhook.missing-body', extra={
                'organization_id': organization.id,
            })
            return HttpResponse(status=400)

        try:
            handler = self.get_handler(request.META['HTTP_X_EVENT_KEY'])
        except KeyError:
            logger.error('bitbucket.webhook.missing-event', extra={
                'organization_id': organization.id,
            })
            return HttpResponse(status=400)

        if not handler:
            return HttpResponse(status=204)

        # TODO(maxbittker) !!!validation is turned off here:
        # try:
        #     method, signature = request.META['HTTP_X_HUB_SIGNATURE'].split('=', 1)
        # except (KeyError, IndexError):
        #     logger.error('bitbucket.webhook.missing-signature', extra={
        #         'organization_id': organization.id,
        #     })
        #     return HttpResponse(status=400)

        # if not self.is_valid_signature(method, body, secret, signature):
        #     logger.error('bitbucket.webhook.invalid-signature', extra={
        #         'organization_id': organization.id,
        #     })
        #     return HttpResponse(status=401)

        try:
            event = json.loads(body.decode('utf-8'))
        except JSONDecodeError:
            logger.error('bitbucket.webhook.invalid-json', extra={
                'organization_id': organization.id,
            }, exc_info=True)
            return HttpResponse(status=400)

        handler()(organization, event)
        return HttpResponse(status=204)