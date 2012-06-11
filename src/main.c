/*
 * Copyright (c) 2012, Guillermo A. Amaral B <g@maral.me>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL GUILLERMO ANTONIO AMARAL BASTIDAS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/wait.h>

#include <security/pam_appl.h>

#include <err.h>
#include <getopt.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "conversation.h"
#include "session.h"

#define SUCCESS  0
#define FAILURE -1

/******************************************************** local declarations */

static void qsu_usage(void);

static int  qsu_initialize(qsu_session *session, char *user, int argc, char *argv[]);
static void qsu_cleanup(qsu_session *session);

static int  qsu_pam_authenticate(qsu_session *session);
static int  qsu_pam_set_items(qsu_session *session);

/*************************************************************** definitions */

int
main(int argc, char *argv[])
{
	qsu_session session;

	int   opt;
	int   status = 1;      /* exit status */
	char *user   = "root"; /* default user */
	
	int   fstatus;         /* fork status */
	pid_t fpid;            /* fork pid */

	/* parse arguments */
	while ((opt = getopt(argc, argv, "hu:")) != FAILURE)
		switch (opt) {
		case 'u':
			user = optarg;
			break;

		default:
			qsu_usage();
			return(1);
		}
	argc -= optind;
	argv += optind;

	/* check for command */
	if (argc <= 0) {
		qsu_usage();
		return(1);
	}

	/*
	 * ** PAM authentication **
	 *
	 * UI frontend will be initiated, pam will start, we will authenticate
	 * and a new session will be started.
	 *
	 */

	if (qsu_initialize(&session, user, argc, argv) == FAILURE ||
	    qsu_pam_set_items(&session)                == FAILURE ||
	    qsu_pam_authenticate(&session)             == FAILURE) {
		qsu_cleanup(&session);
		return(1);
	}


	/*
	 * ** Perform fork **
	 *
	 * If we got this far it means we may proceed.
	 *
	 */

	switch ((fpid = fork())) {

	case -1:
		/* fork failed - abort */
		warn("fork()");
		break;

	case 0:
		/* set uid and groups */
		if (initgroups(session.pwd->pw_name,
		               session.pwd->pw_gid) == FAILURE) {
			warn("initgroups()");
			break;
		}
		if (setgid(session.pwd->pw_gid) == FAILURE) {
			warn("setgid()");
			break;
		}
		if (setuid(session.pwd->pw_uid) == FAILURE) {
			warn("setuid()");
			break;
		}

		execvp(*argv, argv);
		warn("execvp()");
		break;

	default:

		waitpid(fpid, &fstatus, 0);
		status = WEXITSTATUS(fstatus);
	}

	if (status != 0) fprintf(stderr, "Failed!");

	qsu_cleanup(&session);
	return(status);
}

void
qsu_usage(void)
{
	fprintf(stderr, "Usage: qsu [-u <user>] <command>\n");
}

/*****************************************************************************/

int
qsu_initialize(qsu_session *session, char *user, int argc, char *argv[])
{
	memset(session, 0, sizeof(*session));
	session->user = user;
	session->conv.conv = ui_conversation;
	session->conv.appdata_ptr = (void *)&session;
	session->status = 0;
	session->cleanup = 0;

	if ((session->status = pam_start("su", user, &session->conv, &session->handle)) != PAM_SUCCESS)
		return(FAILURE);

	session->cleanup |= qsu_scleanup_started;
	ui_initialize(argc, argv);

	return(SUCCESS);
}

void
qsu_cleanup(qsu_session *session)
{
	if (session->cleanup & qsu_scleanup_session)
		session->status = pam_close_session(session->handle, 0);

	if (session->cleanup & qsu_scleanup_started)
		pam_end(session->handle, session->status);
	
	session->handle = 0;
	session->cleanup = 0;

	ui_finalize();
}

int
qsu_pam_authenticate(qsu_session *session)
{
	if ((session->status = pam_authenticate(session->handle, 0)) != PAM_SUCCESS) {
		ui_error_message("Authentication failed,\nAccess denied.");
		return(FAILURE);
	}

	if ((session->status = pam_acct_mgmt(session->handle, 0)) == PAM_NEW_AUTHTOK_REQD &&
	    (session->status = pam_chauthtok(session->handle, PAM_CHANGE_EXPIRED_AUTHTOK)) != PAM_SUCCESS) {
		ui_error_message("Expired or invalid authentication token,\nAccess denied.");
		return(FAILURE);
	}

	if ((session->status = pam_setcred(session->handle, PAM_ESTABLISH_CRED)) != PAM_SUCCESS ||
	    (session->status = pam_open_session(session->handle, 0)) != PAM_SUCCESS) {
		ui_error_message("Post authentication failed,\nAccess denied.");
		return(FAILURE);
	}

	session->cleanup |= qsu_scleanup_session;

	if ((session->status = pam_get_item(session->handle, PAM_USER, (const void **)&session->user)) != PAM_SUCCESS ||
	    (session->pwd = getpwnam(session->user)) == NULL) {
		ui_error_message("Post authentication failed,\nAccess denied.");
		return(FAILURE);
	}

	return(SUCCESS);
}

int
qsu_pam_set_items(qsu_session *session)
{
	const char *l_user, *l_display;

	l_user    = getlogin();
	l_display = getenv("DISPLAY");

	if ((session->status = pam_set_item(session->handle, PAM_RUSER, l_user))       != PAM_SUCCESS ||
	    (session->status = pam_set_item(session->handle, PAM_TTY, l_display))      != PAM_SUCCESS)
		return(FAILURE);

	return(SUCCESS);
}

