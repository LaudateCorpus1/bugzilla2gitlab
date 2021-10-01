from .config import get_config
from .models import IssueThread
from .utils import bugzilla_login, get_bugzilla_bug, validate_list, get_gitlab_issue


class Migrator:
    def __init__(self, config_path):
        self.conf = get_config(config_path)

    def migrate(self, bug_list):
        """
        Migrate a list of bug ids from Bugzilla to GitLab.
        """
        validate_list(bug_list)
        if self.conf.bugzilla_user:
            bugzilla_login(
                self.conf.bugzilla_base_url,
                self.conf.bugzilla_user,
                self.conf.bugzilla_password,
            )
        for bug in bug_list:
            self.migrate_one(bug)

    def migrate_one(self, bugzilla_bug_id):
        """
        Migrate a single bug from Bugzilla to GitLab.
        """
        print("Trying to migrate bug {}".format(bugzilla_bug_id))
        fields = get_bugzilla_bug(self.conf.bugzilla_base_url, bugzilla_bug_id)

        if not get_gitlab_issue(
                self.conf.gitlab_base_url,
                self.conf.gitlab_project_id,
                fields["bug_id"],
                self.conf.default_headers,
                self.conf.verify,
        ):
            issue_thread = IssueThread(self.conf, fields)
            issue_thread.save()
        else:
            print("Skipping: Issue with id [{}] already exists".format(fields["bug_id"]))
