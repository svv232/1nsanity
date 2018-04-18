#include <stdio.h>
#include <stdbool.h>
#include <string.h>

void init() {
    setvbuf(stdout, NULL, _IONBF, 0);
}

void give_flag() {
    FILE *flag = fopen("flag.txt", "r");
    if (!flag) {
        puts("flag.txt not found. If you were running this against the remote server, you'd have the flag right now. If you are seeing this when connected to the server, something has gone horribly wrong, and you should contact the admins!");
        return;
    }

    char buf[128];
    fgets(buf, sizeof(buf)-1, flag);
    puts(buf);
}

bool check(char *s) {
    unsigned len = strlen(s);
    // no short inputs
    if (len < 20) {
        return false;
    }
    // first few characters are some constants
    if (s[0] != 'a') return false;
    if (s[1] != 'q') return false;
    if (s[2] != 'u') return false;
    if (s[3] != 'a') return false;

    // check palindromeness
    len--;
    for (int i = 0; i <= len; i++,len--) {
        if (s[i] != s[len]) return false;
    }
    return true;
}

int main() {
    char buf[32];
    init();
    puts("Tell me something interesting:");
    fgets(buf, sizeof(buf)-1, stdin);
    char *nl = strchr(buf, '\n');
    if (nl) *nl= '\0';
    if (check(buf)) {
        give_flag();
    } else {
        puts("That doesn't look right! Go reverse some more!");
    }
}
