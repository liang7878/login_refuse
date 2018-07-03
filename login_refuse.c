/* -------------------------------------------------------------------------
 *
 * login_refuse.c
 *
 * IDENTIFICATION
 *		contrib/login_refuse/login_refuse.c
 *
 * -------------------------------------------------------------------------
 */
#include "postgres.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "executor/spi.h"
#include "libpq/auth.h"
#include "port.h"
#include "utils/guc.h"
#include "utils/timestamp.h"


#define LOGIN_REFUSE_FILE "login_refuse"
#define LOGIN_EXPIRE_FILE "login_expire_file"

PG_MODULE_MAGIC;

PG_FUNCTION_INFO_V1(login_refuse_set_expire_time);
PG_FUNCTION_INFO_V1(login_refuse_get_expire_time);
PG_FUNCTION_INFO_V1(login_refuse_get_expire_time_by_username);

void		_PG_init(void);
void		_PG_fini(void);

void		create_record_file(void);
bool		user_exist(char * user_name);
int			failed_count(char * user_name);
int			failed_time_interval(char * user_name);
void		remove_user(char * user_name);
void		insert_user(char * user_name, int count, long timestamp);
void		increase_failed_count(char * user_name);
void		create_expire_file(void);
bool		isExpired(char * username);
bool		user_expire_exist(char *username);
void		user_expire_insert(char *username, long expire_time);
void		user_expire_update(char *username, long expire_time);
void		user_expire_remove(char * user_name);

/* GUC Variables */
static int	login_refuse_minutes;
static int	login_refuse_threshold;
static char *full_path;
static char *expire_path;
/* Original Hook */
static ClientAuthentication_hook_type original_client_auth_hook = NULL;

/*
 * Check authentication
 */
static void
login_refuse_checks(Port *port, int status)
{
	elog(LOG,"-----------------------begin-------------------------");
	/*
	 * Any other plugins which use ClientAuthentication_hook.
	 */
	if (original_client_auth_hook)
		original_client_auth_hook(port, status);

	if (port->hba->auth_method != uaPassword &&
		port->hba->auth_method != uaSCRAM &&
		port->hba->auth_method != uaMD5)
	{
		return;
	}

	create_record_file();
	create_expire_file();

	switch(status)
	{
		case STATUS_OK:
			elog(LOG,"status is STATUS_OK");
			break;
		case STATUS_ERROR:
			elog(LOG,"status is STATUS_ERROR");
			break;
		case STATUS_EOF:
			elog(LOG,"status is STATUS_EOF");
			break;
		case STATUS_FOUND:
			elog(LOG,"status is STATUS_FOUND");
			break;
		case STATUS_WAITING:
			elog(LOG,"status is STATUS_WAITING");
			break;
		default:
			break;
	}

	if (status != STATUS_OK && status != STATUS_ERROR)
	{
		return;
	}

	if(user_expire_exist(port->user_name)) {
		elog(LOG, "enter user exist!");
		if(isExpired(port->user_name)) {
			free(expire_path);
			ereport(FATAL,
				(errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION),
				errmsg("You are not allow to access the database!!!\n"
				"		Your account is expired!!!")));
		}
	}

	elog(LOG,"login_refuse_minutes is %d", login_refuse_minutes);

	if (user_exist(port->user_name))
	{
		if (failed_count(port->user_name) >= login_refuse_threshold)
		{
			if (failed_time_interval(port->user_name) < login_refuse_minutes * 60)
			{
				elog(LOG,"this connection should be refused!");
				free(full_path);
				ereport(FATAL,
					(errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION),
					errmsg("You are not allow to access the database!!!\n"
					"		Please try after %d minutes!!!", login_refuse_minutes)));
			}
			else
			{
				elog(LOG,"222");
				remove_user(port->user_name);
			}
		}
		else
		{
			if (failed_time_interval(port->user_name) > login_refuse_minutes * 60)
			{
				elog(LOG,"233");
				remove_user(port->user_name);
			}
			elog(LOG,"234");
		}
	}

	if (status != STATUS_OK)
	{

		if (!user_exist(port->user_name))
		{
			elog(LOG,"333");
			insert_user(port->user_name, 1, time(NULL));

		}
		else
		{
			elog(LOG,"444");
			increase_failed_count(port->user_name); // update failed time also
		}
	}
	else
	{
		elog(LOG,"445");
		remove_user(port->user_name);
	}
	free(full_path);
	elog(LOG,"------------------------end--------------------------");
}

Datum
login_refuse_set_expire_time(PG_FUNCTION_ARGS)
{
	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 (errmsg("must be superuser to use login_expire"))));
	char	*username = text_to_cstring(PG_GETARG_TEXT_P(0));
	long	timestamp = PG_GETARG_INT64(1);

	elog(LOG, "username: %s, expire time: %ld", username, timestamp);
	create_expire_file();

	if(user_expire_exist(username)) {
		elog(LOG, "enter exist");
		user_expire_update(username, timestamp);
	} else {
		elog(LOG, "enter no exist");
		user_expire_insert(username, timestamp);
	}


	PG_RETURN_VOID();
}

Datum
login_refuse_get_expire_time(PG_FUNCTION_ARGS) {

}

Datum
login_refuse_get_expire_time_by_username(PG_FUNCTION_ARGS) {
	
}

void create_expire_file(void) {
	char *configdir;
	FILE *fp;

	configdir = make_absolute_path(getenv("PGDATA"));
	expire_path = malloc(strlen(configdir)+strlen(LOGIN_EXPIRE_FILE) + 2);
	sprintf(expire_path, "%s/%s", configdir, LOGIN_EXPIRE_FILE);
	elog(LOG, "expire path is %s", expire_path);

	if((fp = fopen(expire_path, "r")) == NULL) {
		fp = fopen(expire_path, "w");
		fclose(fp);
		elog(LOG, "expire file created!");
	} else {
		fclose(fp);
	}

}

bool isExpired(char *username) {
	FILE *fp;
	char *ptr;
	char line[200];
	char id[30];
	time_t expire_time;
	double diff_t;

	elog(LOG, "enter isExpired");

	fp = fopen(expire_path, "r");
	if(fp == NULL) {
		elog(ERROR, "failed to open file login_expire");
	}

	strcpy(id, " ");
	strcat(id, username);
	strcat(id, " ");
	elog(LOG, "enter isExpired1");

	while(!feof(fp)) {
		elog(LOG, "enter isExpired2");
		fgets(line, 200, fp);
		elog(LOG, "enter isExpired2");
		if (strstr(line, id)) {
			elog(LOG, "enter isExpired4");
			ptr = strtok(line, " ");
			elog(LOG, "enter isExpired5: %s", ptr);
			ptr = strtok(NULL, " ");
			elog(LOG, "ptr is $$%s$$", ptr);
			sscanf(ptr, "%ld", &expire_time);
			elog(LOG, "enter isExpired6: $$%ld$$ vs $$%ld$$", expire_time, time(NULL));
			elog(LOG, "strcat");

			elog(LOG, "before compre: %f", difftime(expire_time, time(NULL)));
			elog(LOG, "before compre: %f", difftime(time(NULL), expire_time));
			// if(expire_time<current) {
			// 	elog(LOG, "enter isExpired7, ==========expired=================");
			// 	return true;
			// }
			if(difftime(expire_time, time(NULL)) < 0) {
				elog(LOG, "enter isExpired7, ==========expired=================");
				return true;
			}
			elog(LOG, "after compare");
		}
	}

	return false;

}

// todo check user exist of not
bool user_expire_exist(char *username) {
	FILE *fp;
	char line[200];
	char id[30];

	elog(LOG,"path is %s", expire_path);
	fp = fopen(expire_path, "r");
	if (fp == NULL)
	{
		elog(ERROR,"failed to open file login_refuse");
	}

	strcpy(id, " ");
	strcat(id, username);
	strcat(id, " ");
	elog(LOG,"id is a%sa", id);

	while(!feof(fp))
	{
		fgets(line, 200, fp);
		elog(LOG, "1");
		if (strstr(line, id))
		{
			elog(LOG,"xxxx");
			return true;
		}
	}
	return false;
}

//todo check user expire or not
void user_expire_insert(char *username, long expire_time) {
	FILE *fp;
	fp = fopen(expire_path, "a");

	if(fp == NULL) {
		elog(ERROR, "failed to open login_expire file");
	}
	elog(LOG, "%s %ld", username, expire_time);
	fprintf(fp," %s %ld\n", username, expire_time);
	fclose(fp);
}

//todo update user expire time
void user_expire_update(char *username, long expire_time) {
	user_expire_remove(username);
	user_expire_insert(username, expire_time);
}

void
user_expire_remove(char * user_name)
{
	FILE *fp;
	long length;
	char *buffer;
	char line[200];
	char id[30];

	fp = fopen(expire_path, "r");
	if (fp == NULL)
	{
		elog(ERROR,"failed to open file login_refuse");
	}

	fseek(fp, 0, SEEK_END);
	memset(line, 0x00, 200);
	length = ftell(fp);
	elog(LOG,"length is:%ld", length);
	buffer = (char*)malloc(sizeof(char)*length);
	memset(buffer, 0x00, sizeof(char)*length);
	*buffer = 0;
	rewind(fp);

	elog(LOG,"buffer is:%s", buffer);
	strcpy(id, " ");
	strcat(id, user_name);
	strcat(id, " ");
	elog(LOG,"id is a%sa", id);
	elog(LOG,"line is:%s", line);
	while(!feof(fp))
	{
		fgets(line, 200, fp);
		elog(LOG,"line is:%s", line);
		if (strstr(line, id))
		{
			continue;
		}
		strcat(buffer, line);
		elog(LOG,"buffer is:%s", buffer);
	}
	fclose(fp);
	elog(LOG,"buffer is:%s", buffer);
	fp = fopen(expire_path, "w");
	fputs(buffer, fp);
	fclose(fp);
	free(buffer);
}


/*
 * create the record_file
 */
void
create_record_file(void)
{
	//char	*full_path;
	char	   *configdir;
	FILE	*fp;

	configdir = make_absolute_path(getenv("PGDATA"));
	full_path = malloc(strlen(configdir) + strlen(LOGIN_REFUSE_FILE) + 2);
	sprintf(full_path, "%s/%s", configdir, LOGIN_REFUSE_FILE);
	elog(LOG,"path is %s", full_path);

	if((fp = fopen(full_path,"r")) == NULL)
	{
		fp = fopen(full_path,"w");
		fclose(fp);
		elog(LOG,"file created!!");
	}
	else
	{
		fclose(fp);
	}

}


/*
 * if the user exist in record_file
 */
bool
user_exist(char * user_name)
{
	FILE *fp;
	char line[200];
	char id[30];

	elog(LOG,"path is %s", full_path);
	fp = fopen(full_path, "r");
	if (fp == NULL)
	{
		elog(ERROR,"failed to open file login_refuse");
	}

	strcpy(id, " ");
	strcat(id, user_name);
	strcat(id, " ");
	elog(LOG,"id is a%sa", id);

	while(!feof(fp))
	{
		fgets(line, 200, fp);
		if (strstr(line, id))
		{
			elog(LOG,"xxxx");
			return true;
		}
	}
	return false;
}

/*
 * times user_name has failed
 */
int
failed_count(char * user_name)
{
	FILE *fp;
	char line[200];
	char id[30];
	int fail_count;
	char *ptr;

	elog(LOG,"path is %s", full_path);
	fp = fopen(full_path, "r");
	if (fp == NULL)
	{
		elog(ERROR,"failed to open file login_refuse");
	}

	strcpy(id, " ");
	strcat(id, user_name);
	strcat(id, " ");
	elog(LOG,"id is a%sa", id);

	while(!feof(fp))
	{
		fgets(line, 200, fp);
		if (strstr(line, id))
		{
			elog(LOG,"failed_count");
			//get the failed_count of the line match the user_name
			ptr = strtok(line," ");
			ptr = strtok(NULL, " ");
			elog(LOG,"ptr is $$%s$$",ptr);
			sscanf(ptr,"%d", &fail_count);
			elog(LOG,"failed_count is %d",fail_count);
			return fail_count;
		}
	}
	return 0;
}

/*
 * time interval(in seconds) from last failed for user_name
 */
int
failed_time_interval(char * user_name)
{
	FILE *fp;
	char *ptr;
	char line[200];
	char id[30];
	time_t failed_time;

	elog(LOG,"path is %s", full_path);
	fp = fopen(full_path, "r");
	if (fp == NULL)
	{
		elog(ERROR,"failed to open file login_refuse");
	}

	strcpy(id, " ");
	strcat(id, user_name);
	strcat(id, " ");
	elog(LOG,"id is a%sa", id);

	while(!feof(fp))
	{
		fgets(line, 200, fp);
		if (strstr(line, id))
		{
			elog(LOG,"failed_time_interval");
			//get the failed_time of the line match the user_name
			ptr = strtok(line," ");
			ptr = strtok(NULL, " ");
			ptr = strtok(NULL, " ");
			elog(LOG,"ptr is $$%s$$",ptr);
			sscanf(ptr,"%ld", &failed_time);
			elog(LOG,"failed_time is %ld",failed_time);

			return time(NULL) - failed_time;
		}
	}
	return login_refuse_minutes * 60;
}


/*
 * remove record of user_name from record_file
 */
void
remove_user(char * user_name)
{
	FILE *fp;
	long length;
	char *buffer;
	char line[200];
	char id[30];

	fp = fopen(full_path, "r");
	if (fp == NULL)
	{
		elog(ERROR,"failed to open file login_refuse");
	}

	fseek(fp, 0, SEEK_END);
	memset(line, 0x00, 200);
	length = ftell(fp);
	elog(LOG,"length is:%ld", length);
	buffer = (char*)malloc(sizeof(char)*length);
	memset(buffer, 0x00, sizeof(char)*length);
	*buffer = 0;
	rewind(fp);

	elog(LOG,"buffer is:%s", buffer);
	strcpy(id, " ");
	strcat(id, user_name);
	strcat(id, " ");
	elog(LOG,"id is a%sa", id);
	elog(LOG,"line is:%s", line);
	while(!feof(fp))
	{
		fgets(line, 200, fp);
		elog(LOG,"line is:%s", line);
		if (strstr(line, id))
		{
			continue;
		}
		strcat(buffer, line);
		elog(LOG,"buffer is:%s", buffer);
	}
	fclose(fp);
	elog(LOG,"buffer is:%s", buffer);
	fp = fopen(full_path, "w");
	fputs(buffer, fp);
	fclose(fp);
	free(buffer);
}

/*
 * insert user_name into record_file
 */
void
insert_user(char * user_name, int count, long timestamp)
{
	FILE *fp;

	fp = fopen(full_path, "a");
	if (fp == NULL)
	{
		elog(ERROR,"failed to open file login_refuse");
	}
	elog(LOG," %s %d %ld\n", user_name, count, timestamp);
	fprintf(fp," %s %d %ld\n", user_name, count, timestamp);

	fclose(fp);

}

/*
 * increase failed_count for user_name in record_file
 */
void
increase_failed_count(char * user_name)
{
	int count;

	count = failed_count(user_name) + 1;
	remove_user(user_name);
	insert_user(user_name, count, time(NULL));
}

/*
 * Module Load Callback
 */
void
_PG_init(void)
{
	/* Define custom GUC variables */
	DefineCustomIntVariable("login_refuse.minutes",
							"minutes to refuse users login",
							NULL,
							&login_refuse_minutes,
							0,
							0, INT_MAX,
							PGC_SIGHUP,
							GUC_UNIT_MIN,
							NULL,
							NULL,
							NULL);

	DefineCustomIntVariable("login_refuse.threshold",
							"failed times before refuse users login",
							NULL,
							&login_refuse_threshold,
							0,
							0, INT_MAX,
							PGC_SIGHUP,
							GUC_UNIT_S,
							NULL,
							NULL,
							NULL);
	/* Install Hooks */
	original_client_auth_hook = ClientAuthentication_hook;
	ClientAuthentication_hook = login_refuse_checks;
}

void
_PG_fini(void)
{
	ClientAuthentication_hook = original_client_auth_hook;
}