#include <stdio.h>
#include <stdlib.h>


void dfs(char map[128][128], int n, int i, int j);


int main() {
    int n;
    char map[128][128];

    scanf("%d", &n);
    
    fgets(map[0], 128, stdin);
    for (int i = 0; i < n; i++) {
        fgets(map[i], 128, stdin);
    }

    int count = 0;
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < n; j++) {
            if (map[i][j] == '0') {
                count++;
                dfs(map, n, i, j);
            }
        }
    }
    printf("%d\n", count);

    return 0;
}

void dfs(char map[128][128], int n, int i, int j) {
    if (map[i][j] != '0') {
        return;
    }
    map[i][j] = ' ';

    if (j < (n-1) && map[i][j+1] == '0') {
        dfs(map, n, i, j+1);
    }

    if (j > 0 && map[i][j-1] == '0') {
        dfs(map, n, i, j-1);
    }

    if (i < (n-1) && map[i+1][j] == '0') {
        dfs(map, n, i+1, j);
    }

    if (i > 0 && map[i-1][j] == '0') {
        dfs(map, n, i-1, j);
    }
}
