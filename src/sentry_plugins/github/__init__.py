from __future__ import absolute_import

from sentry.options import (
    FLAG_PRIORITIZE_DISK, FLAG_REQUIRED, register
)

from sentry_plugins.base import assert_package_not_installed

assert_package_not_installed('sentry-github')

# Plugins
register('plugins.github.integration-private-key',
    default='',
    flags=FLAG_REQUIRED | FLAG_PRIORITIZE_DISK,
)
register(
    'plugins.github.integration-hook-secret',
    default='',
    flags=FLAG_REQUIRED | FLAG_PRIORITIZE_DISK,
)
register(
    'plugins.github.integration-app-id',
    default=0,
    flags=FLAG_REQUIRED | FLAG_PRIORITIZE_DISK,
)
register(
    'plugins.github.apps-install-url',
    default='',
    flags=FLAG_REQUIRED | FLAG_PRIORITIZE_DISK,
)
