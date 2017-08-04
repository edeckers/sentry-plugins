from __future__ import absolute_import

from mock import patch

from exam import fixture
from social_auth.models import UserSocialAuth
from sentry.models import Integration, OrganizationIntegration, Repository
from sentry.testutils import PluginTestCase
from sentry.utils import json

from sentry_plugins.github.client import GitHubClient, GitHubAppsClient
from sentry_plugins.github.plugin import GitHubAppsRepositoryProvider, GitHubRepositoryProvider
from sentry_plugins.github.testutils import (
    COMPARE_COMMITS_EXAMPLE, GET_LAST_COMMITS_EXAMPLE, INTSTALLATION_REPOSITORIES_API_RESPONSE,
    LIST_INSTALLATION_API_RESPONSE
)


class GitHubPluginTest(PluginTestCase):
    @fixture
    def provider(self):
        return GitHubRepositoryProvider('github')

    def test_compare_commits(self):
        repo = Repository.objects.create(
            provider='github',
            name='example',
            organization_id=1,
        )

        res = self.provider._format_commits(repo, json.loads(COMPARE_COMMITS_EXAMPLE)['commits'])

        assert res == [
            {
                'author_email': 'support@github.com',
                'author_name': 'Monalisa Octocat',
                'message': 'Fix all the bugs',
                'id': '6dcb09b5b57875f334f61aebed695e2e4193db5e',
                'repository': 'example'
            }
        ]

    def test_get_last_commits(self):
        repo = Repository.objects.create(
            provider='github',
            name='example',
            organization_id=1,
        )

        res = self.provider._format_commits(repo, json.loads(GET_LAST_COMMITS_EXAMPLE)[:10])

        assert res == [
            {
                'author_email': 'support@github.com',
                'author_name': 'Monalisa Octocat',
                'message': 'Fix all the bugs',
                'id': '6dcb09b5b57875f334f61aebed695e2e4193db5e',
                'repository': 'example'
            }
        ]


class GitHubAppsProviderTest(PluginTestCase):
    @fixture
    def provider(self):
        return GitHubAppsRepositoryProvider('github_apps')

    @patch.object(
        GitHubAppsClient,
        'get_repositories',
        return_value=json.loads(INTSTALLATION_REPOSITORIES_API_RESPONSE)
    )
    @patch.object(
        GitHubClient, 'get_installations', return_value=json.loads(LIST_INSTALLATION_API_RESPONSE)
    )
    def test_link_auth(self, *args):
        user = self.create_user()
        organization = self.create_organization()
        UserSocialAuth.objects.create(
            user=user,
            provider='github_apps',
            extra_data={'access_token': 'abcdefg'},
        )

        integration = Integration.objects.create(
            provider='github_apps',
            external_id='1',
        )

        self.provider.link_auth(user, organization, {'integration_id': integration.id})

        assert OrganizationIntegration.objects.filter(
            organization=organization, integration=integration
        ).exists()
