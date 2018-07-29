#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#define FILENAME "profile"

//////////////////////////////////////////////////////////////////////////
//HELPER FUNCTIONS

char *concatPath(char *dir, char *command) {
	int size = strlen(dir)+strlen(command)+1;
	const char delim[2] = "/";
	int len = strlen(dir)-1;

	if (*(dir+len) == '/') {
		char *result = malloc(size);
		strcpy(result, dir);
		strcat(result, command);
		return result;

	} else {
		char *result = malloc(size);
		strcpy(result, dir);
		strcat(result, delim);
		strcat(result, command);
		return result;
	}
}

int countChar(char *s, char c) {
	int count = 0;
	while (*s != '\0') {
		if (*s == c) {
			count ++;
		}
		s++;
	}
	return count;
}


//////////////////////////////////////////////////////////////////////////


/*
*	This function dynamically assigns the environment variables.
*	Syntax checks are made before the assignment is made.
*/
void assignEnv(char *assignee, char **argv, int argc) {
	//Too many arguments for assignment
	if (argc > 3) {
		printf("Invalid arguments\n");
		return;
	}

	int hasEqual = 0;
	char *input = NULL;
	int index = 0;
	int size = 0;

	while (index<argc) {
		char *str = *(argv+index);
		hasEqual += countChar(str, '=');
		size += strlen(str);

		input = realloc(input, (size+1)*sizeof(char));
		if (index == 0) {
			strcpy(input, str);
		} else {
			strcat(input, str);
		}

		index++;

		//Too much equals or assignment has been completed but more arguments to be added
		if (hasEqual > 1 || ((hasEqual == 1 && *(input+size-1) != '=' && index<argc))) {
			printf("Invalid assignment\n");
			free(input);
			input=NULL;
			return;

		}

	}

	int len = strlen(input);

	//NOTE:	For simplicity sake, I will statically define some character indexes
	//	because I am not required to implement variable expansion.
	if (hasEqual == 0) {
		if (len == 5) {
			printf("%s: Is a directory\n", assignee);
		} else {
			printf("%s: command not found\n", input);
		}

	} else {

		//Last character =
		if (*(input+len-1) == '=') {
			printf("Invalid assignment\n");


		//Syntax checks have passed
		} else {
			strcpy(assignee, input+6);

		}

	}

	free(input);
	input=NULL;

}


/*
*	This function forks and executes the program given the full path.
*/
int _execv(char *path, char** argv, char *command) {

	//Fork for a process id
	pid_t pid = fork ();

	//Parent process, wait till child process dies
	if (pid > 0) {
		wait(0);

	//Child process, execute program
	} else if (pid == 0) {

		//Now execute program, given the full path
		execv(path, argv);

		//Prints if an error occurs
		fprintf (stderr, "%s: No such file or directory\n", command);

	} else {
		exit(EXIT_FAILURE);
	}

	return 0;

}


/*
*	This function searches in the paths to find the program
*	that it is located in to execute it.
*/
void search(char *_path, char *command, char **argv) {
	char *fullpath = NULL;
	int ok = -1;

	if (strncmp(command, "./", 2) == 0) {

		if (strlen(command) == 2) {
			printf("./: Is a directory\n");
			ok = 0;

		//Execute program in current working directory
		} else {
			char cwd[512];
			getcwd(cwd,sizeof(cwd));
			fullpath = concatPath(cwd, command+2);
			ok = _execv(fullpath, argv, command);
		}

	} else {
		//copy the path, to not damage it
		char path[512]; 
		strcpy(path, _path);

		const char delim[2] = ":";
		struct stat statbuf;

		char *dirpath = strtok(path, delim);

		while (dirpath != NULL) {

			fullpath = concatPath(dirpath, command);

			if (stat(fullpath, &statbuf) == 0) {
				//program has been found
				ok = _execv(fullpath, argv, command);
			
			}

			free(fullpath);
			fullpath = NULL;

	      		dirpath = strtok(NULL, delim);
		}

	}

	//Error
	if (ok != 0) {
		printf("%s: command not found\n", command);
	}
}


/*
*	This function acts upon the cd command
*/
void _chdir(char *home, char **argv, int argc) {
	int ok = -1;
	
	char *path = home;
	if (argc > 1) {
		path = *(argv+1);
	}

	ok = chdir(path);
	if (ok < 0) {
		printf("%s: No such file or directory\n", path);
	}
}


//////////////////////////////////////////////////////////////////////////
//Main and parser

/*
*	This function break the input into tokens and uses
*	the command to decide on the execution.
*/
void parse(char *home, char *path, char *input) {

	char **argv = NULL;
	const char delim[3] = " ";

	char *temp = strtok(input, delim);
	char *command = temp;
	int argc = 0;
	
	//Tokenize the input
	while (temp != NULL) {

		argv = realloc(argv, (argc+1)*sizeof(char*));
		*(argv+argc) = temp;
      		temp = strtok(NULL, delim);
		argc++;
	}
	argv = realloc(argv, (argc+1)*sizeof(char*));
	*(argv+argc) = '\0';


	//Decide on the execution
	if (command != NULL) {
		if (strcmp(command, "exit") == 0) {
			exit(EXIT_SUCCESS);

		} else if (strcmp(command, "cd") == 0) {
			_chdir(home, argv, argc);
		
		} else if (strncmp(command, "$HOME", 5) == 0) {
			assignEnv(home, argv, argc);

		} else if (strncmp(command, "$PATH", 5) == 0) {
			assignEnv(path, argv, argc);

		} else {
			search(path, command, argv);
		}
	}

	free(argv);
	argv = NULL;
}



/*
*	This function reads in the file, gets the environment
*	variables before running the shell.
*/
int main() {

	char buffer[1024], cwd[512];
	char home[512] = "", path[512] = "";

	//Get the current working directory
	getcwd(cwd,sizeof(cwd));


	//Check if profile file exist
	if (access(FILENAME, F_OK)) {
		printf("Error: %s file not found\n",FILENAME);
		exit(EXIT_FAILURE);
	}


	//Open existing file and find environment variables
	FILE *finput = fopen(FILENAME, "r");

	char *input = fgets(buffer, sizeof(buffer), finput);
	while (input != NULL) {
		int len = strlen(input)-1; //excluding \n
		*(input+len) = '\0';

		//String slice the directories
		if (strncmp(input, "HOME=", 5) == 0) {
			strcpy(home, input+5);

		} else if (strncmp(input, "PATH=", 5) == 0) {
			strcpy(path, input+5);

		}

		input = fgets(buffer, sizeof(buffer), finput);		
	}
	fclose(finput);


	//Check if environment variables have been assigned
	if (strlen(home) == 0 || strlen(path) == 0) {
		printf("Error: environment variables not found\n");
		exit(EXIT_FAILURE);
	}
	

	printf("\nHOME=%s\n", home);
	printf("PATH=%s\n\n", path);


	//Run the shell loop
	printf("TUAN-SHELL:%s> ", cwd);
	input = fgets(buffer, sizeof(buffer), stdin);

	while (input != NULL) {

		//Exclude \n and replace with \0
		int len = strlen(input)-1;
		if (len > 0) {
			*(input+len) = '\0';
			parse(home, path, input);

			getcwd(cwd,sizeof(cwd));
		}

		//New round
		printf("TUAN-SHELL:%s> ", cwd);
		input = fgets(buffer, sizeof(buffer), stdin);

	}


 	return 0;
}
