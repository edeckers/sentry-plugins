from __future__ import absolute_import

import logging
import six

from uuid import uuid4

from sentry.app import locks
from sentry.exceptions import PluginError
from sentry.models import OrganizationOption
from sentry.plugins import providers
from sentry.plugins.bases.issue2 import IssuePlugin2
from sentry.utils.http import absolute_uri

from sentry_plugins.base import CorePluginMixin
from sentry_plugins.exceptions import ApiError, ApiUnauthorized
from sentry_plugins.utils import get_secret_field_config
from .client import GitLabClient

# TODO(dcramer): Move these to shared constants and reuse with other plugins
ERR_INTERNAL = 'An internal error occurred with the integration and the Sentry team has been notified'

ERR_UNAUTHORIZED = 'Unauthorized: either your access token was invalid or you do not have access'


class GitLabPlugin(CorePluginMixin, IssuePlugin2):
    description = 'Integrate GitLab issues by linking a repository to a project'
    slug = 'gitlab'
    title = 'GitLab'
    conf_title = title
    conf_key = 'gitlab'

    def is_configured(self, request, project, **kwargs):
        return bool(
            self.get_option('gitlab_repo', project) and self.get_option('gitlab_token', project) and
            self.get_option('gitlab_url', project)
        )

    def get_new_issue_fields(self, request, group, event, **kwargs):
        fields = super(GitLabPlugin, self).get_new_issue_fields(request, group, event, **kwargs)
        return [
            {
                'name': 'repo',
                'label': 'Repository',
                'default': self.get_option('gitlab_repo', group.project),
                'type': 'text',
                'readonly': True
            }
        ] + fields + [
            {
                'name': 'assignee',
                'label': 'Assignee',
                'default': '',
                'type': 'select',
                'required': False,
                'choices': self.get_allowed_assignees(request, group),
            }, {
                'name': 'labels',
                'label': 'Labels',
                'default': self.get_option('gitlab_labels', group.project),
                'type': 'text',
                'placeholder': 'e.g. high, bug',
                'required': False,
            }
        ]

    def get_link_existing_issue_fields(self, request, group, event, **kwargs):
        return [
            {
                'name': 'issue_id',
                'label': 'Issue #',
                'default': '',
                'placeholder': 'e.g. 1543',
                'type': 'text',
            }, {
                'name': 'comment',
                'label': 'Comment',
                'default': absolute_uri(group.get_absolute_url()),
                'type': 'textarea',
                'help': ('Leave blank if you don\'t want to '
                         'add a comment to the GitLab issue.'),
                'required': False
            }
        ]

    def get_allowed_assignees(self, request, group):
        repo = self.get_option('gitlab_repo', group.project)
        client = self.get_client(group.project)
        try:
            response = client.list_project_members(repo)
        except ApiError as e:
            self.raise_error(e)
        users = tuple((u['id'], u['username']) for u in response)

        return (('', '(Unassigned)'), ) + users

    def get_new_issue_title(self, **kwargs):
        return 'Create GitLab Issue'

    def get_client(self, project):
        url = self.get_option('gitlab_url', project).rstrip('/')
        token = self.get_option('gitlab_token', project)

        return GitLabClient(url, token)

    def create_issue(self, request, group, form_data, **kwargs):
        repo = self.get_option('gitlab_repo', group.project)

        client = self.get_client(group.project)

        try:
            response = client.create_issue(
                repo, {
                    'title': form_data['title'],
                    'description': form_data['description'],
                    'labels': form_data.get('labels'),
                    'assignee_id': form_data.get('assignee'),
                }
            )
        except Exception as e:
            self.raise_error(e)

        return response['iid']

    def link_issue(self, request, group, form_data, **kwargs):
        client = self.get_client(group.project)
        repo = self.get_option('gitlab_repo', group.project)
        try:
            issue = client.get_issue(
                repo=repo,
                issue_id=form_data['issue_id'],
            )
        except Exception as e:
            self.raise_error(e)

        comment = form_data.get('comment')
        if comment:
            try:
                client.create_note(
                    repo=repo,
                    global_issue_id=issue['id'],
                    data={
                        'body': comment,
                    },
                )
            except Exception as e:
                self.raise_error(e)

        return {'title': issue['title']}

    def raise_error(self, exc):
        if isinstance(exc, ApiUnauthorized):
            raise PluginError(ERR_UNAUTHORIZED)
        elif isinstance(exc, ApiError):
            raise PluginError(
                'Error Communicating with GitLab (HTTP %s): %s' % (
                    exc.code, exc.json.get('message', 'unknown error')
                    if exc.json else 'unknown error',
                )
            )
        elif isinstance(exc, PluginError):
            raise
        else:
            self.logger.exception(six.text_type(exc))
            raise PluginError(ERR_INTERNAL)

    def get_issue_label(self, group, issue_id, **kwargs):
        return 'GL-{}'.format(issue_id)

    def get_issue_url(self, group, issue_id, **kwargs):
        url = self.get_option('gitlab_url', group.project).rstrip('/')
        repo = self.get_option('gitlab_repo', group.project)

        return '{}/{}/issues/{}'.format(url, repo, issue_id)

    def get_configure_plugin_fields(self, request, project, **kwargs):
        gitlab_token = self.get_option('gitlab_token', project)
        secret_field = get_secret_field_config(
            gitlab_token, 'Enter your GitLab API token.', include_prefix=True
        )
        secret_field.update(
            {
                'name': 'gitlab_token',
                'label': 'Access Token',
                'placeholder': 'e.g. g5DWFtLzaztgYFrqhVfE'
            }
        )

        return [
            {
                'name': 'gitlab_url',
                'label': 'GitLab URL',
                'type': 'url',
                'default': 'https://gitlab.com',
                'placeholder': 'e.g. https://gitlab.example.com',
                'required': True,
                'help': 'Enter the URL for your GitLab server.'
            }, secret_field, {
                'name': 'gitlab_repo',
                'label': 'Repository Name',
                'type': 'text',
                'placeholder': 'e.g. getsentry/sentry',
                'required': True,
                'help': 'Enter your repository name, including the owner.'
            }, {
                'name': 'gitlab_labels',
                'label': 'Issue Labels',
                'type': 'text',
                'placeholder': 'e.g. high, bug',
                'required': False,
                'help': 'Enter the labels you want to auto assign to new issues.',
            }
        ]

    def validate_config(self, project, config, actor=None):
        url = config['gitlab_url'].rstrip('/')
        token = config['gitlab_token']
        repo = config['gitlab_repo']

        client = GitLabClient(url, token)
        try:
            client.get_project(repo)
        except Exception as e:
            self.raise_error(e)
        return config

    def setup(self, bindings):
        bindings.add('repository.provider', GitLabRepositoryProvider, id='gitlab')


class GitLabRepositoryProvider(providers.RepositoryProvider):
    name = 'GitLab'
    auth_provider = 'gitlab'
    logger = logging.getLogger('sentry.plugins.gitlab')

    def get_config(self):
        return [
            {
                'name': 'name',
                'label': 'Repository Name',
                'type': 'text',
                'placeholder': 'e.g. getsentry/sentry',
                'help': 'Enter your repository name, including the owner.',
                'required': True,
            }
        ]

    def validate_config(self, organization, config, actor=None):
        """
        ```
        if config['foo'] and not config['bar']:
            raise PluginError('You cannot configure foo with bar')
        return config
        ```
        """
        if config.get('name'):
            client = self.get_client(actor)
            try:
                repo = client.get_repo(config['name'])
            except Exception as e:
                self.raise_error(e)
            else:
                config['external_id'] = six.text_type(repo['id'])
        return config

    def get_webhook_secret(self, organization):
        lock = locks.get('gitlab:webhook-secret:{}'.format(organization.id), duration=60)
        with lock.acquire():
            # TODO(dcramer): get_or_create would be a useful native solution
            secret = OrganizationOption.objects.get_value(
                organization=organization,
                key='gitlab:webhook_secret',
            )
            if secret is None:
                secret = uuid4().hex + uuid4().hex
                OrganizationOption.objects.set_value(
                    organization=organization,
                    key='gitlab:webhook_secret',
                    value=secret,
                )
        return secret

    def create_repository(self, organization, data, actor=None):
        if actor is None:
            raise NotImplementedError('Cannot create a repository anonymously')

        client = self.get_client(actor)

        try:
            resp = client.create_hook(
                data['name'], {
                    'name': 'web',
                    'active': True,
                    'events': ['push'],
                    'config': {
                        'url':
                        absolute_uri(
                            '/plugins/gitlab/organizations/{}/webhook/'.format(organization.id)
                        ),
                        'content_type':
                        'json',
                        'secret':
                        self.get_webhook_secret(organization),
                    },
                }
            )
        except Exception as e:
            self.raise_error(e)
        else:
            return {
                'name': data['name'],
                'external_id': data['external_id'],
                'url': self.url + data['name'],
                'config': {
                    'name': data['name'],
                    'webhook_id': resp['id'],
                }
            }

    def delete_repository(self, repo, actor=None):
        if actor is None:
            raise NotImplementedError('Cannot delete a repository anonymously')

        client = self.get_client(actor)
        try:
            client.delete_hook(repo.config['name'], repo.config['webhook_id'])
        except ApiError as exc:
            if exc.code == 404:
                return
            raise

    def _format_commits(self, repo, commit_list):
        return [
            {
                'id': c['id'],
                'repository': repo.name,
                'author_email': c['author_email'],
                'author_name': c['author_name'],
                'message': c['message'],
            } for c in commit_list
        ]

    def compare_commits(self, repo, start_sha, end_sha, actor=None):
        if actor is None:
            raise NotImplementedError('Cannot fetch commits anonymously')

        client = self.get_client(actor)
        # use config name because that is kept in sync via webhooks
        name = repo.config['name']
        if start_sha is None:
            try:
                res = client.get_last_commits(name, end_sha)
            except Exception as e:
                self.raise_error(e)
            else:
                return self._format_commits(repo, res[:10])
        else:
            try:
                res = client.compare_commits(name, start_sha, end_sha)
            except Exception as e:
                self.raise_error(e)
            else:
                return self._format_commits(repo, res['commits'])
