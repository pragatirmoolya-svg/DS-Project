/*
 * CYBERSHIELD - Intelligent Cyber Threat Log Analyzer
 *
 * Data structures used (and why):
 *   Queue        - incoming logs wait here and are processed in arrival order
 *   Linked list  - permanent, dynamic store of all processed log records
 *   Hash table   - O(1) average counters per IP and per username (chaining)
 *   BST          - IP statistics kept sorted by IP for search and ordered reports
 *   Stack        - most recent events, newest first, for quick review
 *
 * Alerts are SUSPICIOUS PATTERNS that need investigation. They are not proof
 * that an IP or user is malicious. Detection thresholds are configurable.
 *
 * Build:  gcc -Wall -Wextra -o cybershield cybershield.c
 * CSV format: ip,username,timestamp,status   (status = Success | Failed)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#define IP_LEN      20
#define USER_LEN    32
#define TIME_LEN    24
#define TABLE_SIZE  101
#define LINE_LEN    256
#define RECENT_SHOW 5

/* ------------------------------------------------------------------ */
/* Core types                                                          */
/* ------------------------------------------------------------------ */

typedef struct Log {
    int  id;
    char ip[IP_LEN];
    char user[USER_LEN];
    char time[TIME_LEN];
    int  success;               /* 1 = Success, 0 = Failed */
    struct Log *next;           /* linked list link */
} Log;

typedef struct Stat {           /* per-IP or per-user counters */
    char key[USER_LEN];
    int  total, failed, success;
    int  consec_fail;           /* current failure streak */
    int  max_consec_fail;
    int  breach;                /* successes that followed a long failure streak */
    struct Stat *next;          /* hash chain */
} Stat;

typedef struct { Stat *bucket[TABLE_SIZE]; } HashTable;

typedef struct BSTNode {
    Stat *s;
    struct BSTNode *left, *right;
} BSTNode;

typedef struct QNode { Log *log; struct QNode *next; } QNode;
typedef struct { QNode *front, *rear; int size; } Queue;

typedef struct SNode { Log data; struct SNode *below; } SNode;

typedef struct {
    int fail_th;        /* failed attempts from one IP that raise an alert   */
    int user_fail_th;   /* failed attempts against one account               */
    int freq_th;        /* total attempts from one IP = unusual frequency    */
} Config;

/* ------------------------------------------------------------------ */
/* Global state                                                        */
/* ------------------------------------------------------------------ */

static Log      *head = NULL, *tail = NULL;
static int       log_count = 0, next_id = 1;
static Queue     pending = {NULL, NULL, 0};
static HashTable ip_table, user_table;
static BSTNode  *bst_root = NULL;
static SNode    *stack_top = NULL;
static Config    cfg = {3, 5, 8};

/* ------------------------------------------------------------------ */
/* Small helpers                                                       */
/* ------------------------------------------------------------------ */

static void trim(char *s) {
    size_t n = strlen(s);
    while (n && isspace((unsigned char)s[n - 1])) s[--n] = '\0';
    char *p = s;
    while (*p && isspace((unsigned char)*p)) p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
}

static void cleanup(void);

static void read_line(const char *prompt, char *buf, size_t size) {
    printf("%s", prompt);
    fflush(stdout);
    if (!fgets(buf, (int)size, stdin)) {   /* end of input: exit instead of looping forever */
        cleanup();
        exit(0);
    }
    trim(buf);
}

static int read_int(const char *prompt, int fallback) {
    char buf[32];
    read_line(prompt, buf, sizeof buf);
    if (buf[0] == '\0') return fallback;
    return atoi(buf);
}

static int valid_ip(const char *s) {
    int a, b, c, d; char extra;
    if (sscanf(s, "%d.%d.%d.%d%c", &a, &b, &c, &d, &extra) != 4) return 0;
    return a >= 0 && a <= 255 && b >= 0 && b <= 255 &&
           c >= 0 && c <= 255 && d >= 0 && d <= 255;
}

static void now_string(char *out, size_t n) {
    time_t t = time(NULL);
    strftime(out, n, "%Y-%m-%d %H:%M:%S", localtime(&t));
}

/* ------------------------------------------------------------------ */
/* Queue                                                               */
/* ------------------------------------------------------------------ */

static void enqueue(Queue *q, Log *l) {
    QNode *n = malloc(sizeof *n);
    if (!n) { fprintf(stderr, "Out of memory\n"); exit(1); }
    n->log = l; n->next = NULL;
    if (q->rear) q->rear->next = n; else q->front = n;
    q->rear = n;
    q->size++;
}

static Log *dequeue(Queue *q) {
    if (!q->front) return NULL;
    QNode *n = q->front;
    Log *l = n->log;
    q->front = n->next;
    if (!q->front) q->rear = NULL;
    free(n);
    q->size--;
    return l;
}

/* ------------------------------------------------------------------ */
/* Hash table (separate chaining)                                      */
/* ------------------------------------------------------------------ */

static unsigned hash_str(const char *s) {
    unsigned h = 5381;
    while (*s) h = h * 33 + (unsigned char)*s++;
    return h % TABLE_SIZE;
}

static Stat *ht_get(HashTable *t, const char *key, int create, int *created) {
    unsigned i = hash_str(key);
    for (Stat *s = t->bucket[i]; s; s = s->next)
        if (strcmp(s->key, key) == 0) { if (created) *created = 0; return s; }
    if (!create) return NULL;
    Stat *s = calloc(1, sizeof *s);
    if (!s) { fprintf(stderr, "Out of memory\n"); exit(1); }
    strncpy(s->key, key, USER_LEN - 1);
    s->next = t->bucket[i];
    t->bucket[i] = s;
    if (created) *created = 1;
    return s;
}

static void ht_free(HashTable *t) {
    for (int i = 0; i < TABLE_SIZE; i++) {
        Stat *s = t->bucket[i];
        while (s) { Stat *n = s->next; free(s); s = n; }
        t->bucket[i] = NULL;
    }
}

/* ------------------------------------------------------------------ */
/* Binary search tree (keyed by IP string)                             */
/* ------------------------------------------------------------------ */

static BSTNode *bst_insert(BSTNode *root, Stat *s) {
    if (!root) {
        BSTNode *n = malloc(sizeof *n);
        if (!n) { fprintf(stderr, "Out of memory\n"); exit(1); }
        n->s = s; n->left = n->right = NULL;
        return n;
    }
    if (strcmp(s->key, root->s->key) < 0) root->left  = bst_insert(root->left, s);
    else                                  root->right = bst_insert(root->right, s);
    return root;
}

static Stat *bst_find(BSTNode *root, const char *key) {
    while (root) {
        int c = strcmp(key, root->s->key);
        if (c == 0) return root->s;
        root = (c < 0) ? root->left : root->right;
    }
    return NULL;
}

static void bst_inorder(BSTNode *root, void (*fn)(Stat *, void *), void *ctx) {
    if (!root) return;
    bst_inorder(root->left, fn, ctx);
    fn(root->s, ctx);
    bst_inorder(root->right, fn, ctx);
}

static void bst_free(BSTNode *root) {
    if (!root) return;
    bst_free(root->left);
    bst_free(root->right);
    free(root);
}

/* ------------------------------------------------------------------ */
/* Stack of recent events (stores copies, so deletes are safe)         */
/* ------------------------------------------------------------------ */

static void stack_push(const Log *l) {
    SNode *n = malloc(sizeof *n);
    if (!n) { fprintf(stderr, "Out of memory\n"); exit(1); }
    n->data = *l;
    n->data.next = NULL;
    n->below = stack_top;
    stack_top = n;
}

static void stack_free(void) {
    while (stack_top) { SNode *n = stack_top->below; free(stack_top); stack_top = n; }
}

/* ------------------------------------------------------------------ */
/* Log creation and processing                                         */
/* ------------------------------------------------------------------ */

static Log *new_log(const char *ip, const char *user, const char *ts, int success) {
    Log *l = calloc(1, sizeof *l);
    if (!l) { fprintf(stderr, "Out of memory\n"); exit(1); }
    l->id = next_id++;
    strncpy(l->ip, ip, IP_LEN - 1);
    strncpy(l->user, user, USER_LEN - 1);
    strncpy(l->time, ts, TIME_LEN - 1);
    l->success = success;
    return l;
}

static void update_stat(Stat *s, int success) {
    s->total++;
    if (success) {
        s->success++;
        if (s->consec_fail >= cfg.fail_th) s->breach++;
        s->consec_fail = 0;
    } else {
        s->failed++;
        s->consec_fail++;
        if (s->consec_fail > s->max_consec_fail) s->max_consec_fail = s->consec_fail;
    }
}

static void analyze_event(const Log *l) {
    int created;
    Stat *ip = ht_get(&ip_table, l->ip, 1, &created);
    if (created) bst_root = bst_insert(bst_root, ip);
    update_stat(ip, l->success);
    update_stat(ht_get(&user_table, l->user, 1, NULL), l->success);
    stack_push(l);
}

static void list_append(Log *l) {
    if (tail) tail->next = l; else head = l;
    tail = l;
    log_count++;
}

/* Take every waiting log off the queue, store it, and analyze it. */
static int process_queue(void) {
    int n = 0;
    Log *l;
    while ((l = dequeue(&pending)) != NULL) {
        list_append(l);
        analyze_event(l);
        n++;
    }
    return n;
}

/* Recompute all statistics from the linked list (after delete / config change). */
static void rebuild_stats(void) {
    bst_free(bst_root); bst_root = NULL;
    ht_free(&ip_table);
    ht_free(&user_table);
    stack_free();
    for (Log *l = head; l; l = l->next) analyze_event(l);
}

/* ------------------------------------------------------------------ */
/* Module 1: log management                                            */
/* ------------------------------------------------------------------ */

static void add_log(void) {
    char ip[IP_LEN], user[USER_LEN], ts[TIME_LEN], st[8];
    read_line("IP address (e.g. 192.168.1.10): ", ip, sizeof ip);
    if (!valid_ip(ip)) { printf("Invalid IP address.\n"); return; }
    read_line("Username: ", user, sizeof user);
    if (user[0] == '\0' || strchr(user, ',')) { printf("Invalid username.\n"); return; }
    read_line("Timestamp (blank = now): ", ts, sizeof ts);
    if (ts[0] == '\0') now_string(ts, sizeof ts);
    if (strchr(ts, ',')) { printf("Invalid timestamp.\n"); return; }
    read_line("Status (S = Success, F = Failed): ", st, sizeof st);
    char c = (char)tolower((unsigned char)st[0]);
    if (c != 's' && c != 'f') { printf("Status must be S or F.\n"); return; }

    Log *l = new_log(ip, user, ts, c == 's');
    enqueue(&pending, l);                 /* arrives in the queue ... */
    process_queue();                      /* ... and is processed in order */
    printf("Log #%d added.\n", l->id);
}

static void display_logs(void) {
    if (!head) { printf("No logs recorded.\n"); return; }
    printf("\n%-5s %-16s %-14s %-20s %s\n", "ID", "IP", "USER", "TIME", "STATUS");
    printf("-------------------------------------------------------------------\n");
    for (Log *l = head; l; l = l->next)
        printf("%-5d %-16s %-14s %-20s %s\n", l->id, l->ip, l->user, l->time,
               l->success ? "Success" : "Failed");
    printf("Total: %d log(s)\n", log_count);
}

static void search_by_ip(void) {
    char ip[IP_LEN];
    read_line("IP to search: ", ip, sizeof ip);
    Stat *s = bst_find(bst_root, ip);        /* BST lookup */
    if (!s) { printf("No logs found for %s.\n", ip); return; }
    printf("\n%s: %d attempt(s), %d success, %d failed\n", s->key, s->total, s->success, s->failed);
    printf("%-5s %-14s %-20s %s\n", "ID", "USER", "TIME", "STATUS");
    for (Log *l = head; l; l = l->next)
        if (strcmp(l->ip, ip) == 0)
            printf("%-5d %-14s %-20s %s\n", l->id, l->user, l->time, l->success ? "Success" : "Failed");
}

static void delete_log(void) {
    int id = read_int("Log ID to delete: ", -1);
    Log *prev = NULL, *cur = head;
    while (cur && cur->id != id) { prev = cur; cur = cur->next; }
    if (!cur) { printf("No log with ID %d.\n", id); return; }
    if (prev) prev->next = cur->next; else head = cur->next;
    if (cur == tail) tail = prev;
    free(cur);
    log_count--;
    rebuild_stats();
    printf("Log #%d deleted and statistics recalculated.\n", id);
}

/* ------------------------------------------------------------------ */
/* Module 2: login activity analysis                                   */
/* ------------------------------------------------------------------ */

static void sum_cb(Stat *s, void *ctx) {
    int *t = ctx;               /* t[0]=total t[1]=success t[2]=failed */
    t[0] += s->total; t[1] += s->success; t[2] += s->failed;
}

typedef struct { Stat **arr; int n; } StatList;

static void collect_cb(Stat *s, void *ctx) {
    StatList *L = ctx;
    L->arr[L->n++] = s;
}

static int cmp_total_desc(const void *a, const void *b) {
    const Stat *x = *(Stat *const *)a, *y = *(Stat *const *)b;
    if (y->total != x->total) return y->total - x->total;
    return strcmp(x->key, y->key);
}

static int count_ips(void) {
    int n = 0;
    for (int i = 0; i < TABLE_SIZE; i++)
        for (Stat *s = ip_table.bucket[i]; s; s = s->next) n++;
    return n;
}

static void analyze_logins(void) {
    if (!log_count) { printf("No logs to analyze.\n"); return; }
    int t[3] = {0, 0, 0};
    bst_inorder(bst_root, sum_cb, t);

    int n = count_ips();
    StatList L = { malloc((size_t)n * sizeof(Stat *)), 0 };
    bst_inorder(bst_root, collect_cb, &L);
    qsort(L.arr, (size_t)L.n, sizeof(Stat *), cmp_total_desc);

    printf("\n--- Login Activity Analysis ---\n");
    printf("Total login attempts : %d\n", t[0]);
    printf("Successful logins    : %d\n", t[1]);
    printf("Failed logins        : %d (%.1f%%)\n", t[2], 100.0 * t[2] / t[0]);
    printf("Unique IP addresses  : %d\n", n);
    if (L.n) printf("Most frequent IP     : %s (%d attempts)\n", L.arr[0]->key, L.arr[0]->total);
    printf("\nIPs with repeated failures (>= 2 in a row):\n");
    int any = 0;
    for (int i = 0; i < L.n; i++)
        if (L.arr[i]->max_consec_fail >= 2) {
            printf("  %-16s longest failure streak: %d\n", L.arr[i]->key, L.arr[i]->max_consec_fail);
            any = 1;
        }
    if (!any) printf("  none\n");
    free(L.arr);
}

/* ------------------------------------------------------------------ */
/* Module 3: suspicious activity detection                             */
/* ------------------------------------------------------------------ */

static void alert_ip_cb(Stat *s, void *ctx) {
    int *cnt = ctx;
    if (s->breach > 0) {
        printf("[HIGH]   %-16s success after %d+ failures in a row (%d time(s)) - possible account compromise\n",
               s->key, cfg.fail_th, s->breach);
        (*cnt)++;
    }
    if (s->failed >= cfg.fail_th) {
        printf("[MEDIUM] %-16s %d failed attempts (longest streak %d) - repeated failed logins\n",
               s->key, s->failed, s->max_consec_fail);
        (*cnt)++;
    }
    if (s->total >= cfg.freq_th) {
        printf("[LOW]    %-16s %d attempts - unusually high login frequency\n", s->key, s->total);
        (*cnt)++;
    }
}

static int run_detection(void) {
    int cnt = 0;
    bst_inorder(bst_root, alert_ip_cb, &cnt);
    for (int i = 0; i < TABLE_SIZE; i++)
        for (Stat *u = user_table.bucket[i]; u; u = u->next)
            if (u->failed >= cfg.user_fail_th) {
                printf("[MEDIUM] account '%s' had %d failed logins - abnormal account activity\n",
                       u->key, u->failed);
                cnt++;
            }
    return cnt;
}

static void detect_suspicious(void) {
    if (!log_count) { printf("No logs to analyze.\n"); return; }
    printf("\n--- Suspicious Activity (rules: fail>=%d, account fail>=%d, frequency>=%d) ---\n",
           cfg.fail_th, cfg.user_fail_th, cfg.freq_th);
    int n = run_detection();
    if (!n) printf("No suspicious patterns detected.\n");
    else printf("\n%d alert(s). These are patterns to investigate, not confirmed attacks.\n", n);
}

/* ------------------------------------------------------------------ */
/* Module 4: reports                                                   */
/* ------------------------------------------------------------------ */

static void top_ips(int limit) {
    int n = count_ips();
    if (!n) { printf("No data.\n"); return; }
    StatList L = { malloc((size_t)n * sizeof(Stat *)), 0 };
    bst_inorder(bst_root, collect_cb, &L);
    qsort(L.arr, (size_t)L.n, sizeof(Stat *), cmp_total_desc);
    printf("%-5s %-16s %-8s %-8s %s\n", "RANK", "IP", "TOTAL", "FAILED", "SUCCESS");
    for (int i = 0; i < L.n && i < limit; i++)
        printf("%-5d %-16s %-8d %-8d %d\n", i + 1, L.arr[i]->key,
               L.arr[i]->total, L.arr[i]->failed, L.arr[i]->success);
    free(L.arr);
}

static void display_top_ips(void) {
    int k = read_int("How many IPs to show (default 5): ", 5);
    if (k < 1) k = 5;
    printf("\n--- Top Active IPs ---\n");
    top_ips(k);
}

static void generate_report(void) {
    if (!log_count) { printf("No logs to report on.\n"); return; }
    int t[3] = {0, 0, 0};
    bst_inorder(bst_root, sum_cb, t);

    printf("\n================ SECURITY REPORT ================\n");
    printf("Total events        : %d\n", t[0]);
    printf("Successful logins   : %d\n", t[1]);
    printf("Failed logins       : %d\n", t[2]);
    printf("Unique IPs          : %d\n\n", count_ips());
    printf("Top active IPs:\n");
    top_ips(5);
    printf("\nAlerts:\n");
    int n = run_detection();
    if (!n) printf("None.\n");
    printf("\nSuspicious events flagged: %d\n", n);
    printf("Note: alerts are suspicious patterns for investigation,\n"
           "      not proof that any IP or user is malicious.\n");
    printf("=================================================\n");
}

static void show_recent(void) {
    if (!stack_top) { printf("No events yet.\n"); return; }
    printf("\n--- Last %d events (newest first, from stack) ---\n", RECENT_SHOW);
    int i = 0;
    for (SNode *n = stack_top; n && i < RECENT_SHOW; n = n->below, i++)
        printf("#%-4d %-16s %-12s %-20s %s\n", n->data.id, n->data.ip, n->data.user,
               n->data.time, n->data.success ? "Success" : "Failed");
}

/* ------------------------------------------------------------------ */
/* File handling and configuration                                     */
/* ------------------------------------------------------------------ */

static void load_csv(void) {
    char path[LINE_LEN];
    read_line("CSV file path (default sample_logs.csv): ", path, sizeof path);
    if (path[0] == '\0') strcpy(path, "sample_logs.csv");
    FILE *f = fopen(path, "r");
    if (!f) { printf("Cannot open '%s'.\n", path); return; }

    char line[LINE_LEN];
    int lineno = 0, loaded = 0, skipped = 0;
    while (fgets(line, sizeof line, f)) {
        lineno++;
        trim(line);
        if (line[0] == '\0') continue;
        if (lineno == 1 && !isdigit((unsigned char)line[0])) continue;   /* header */
        char ip[IP_LEN], user[USER_LEN], ts[TIME_LEN], st[16];
        if (sscanf(line, " %19[^,],%31[^,],%23[^,],%15[^,\n]", ip, user, ts, st) != 4) { skipped++; continue; }
        trim(ip); trim(user); trim(ts); trim(st);
        char c = (char)tolower((unsigned char)st[0]);
        if (!valid_ip(ip) || user[0] == '\0' || (c != 's' && c != 'f')) { skipped++; continue; }
        enqueue(&pending, new_log(ip, user, ts, c == 's'));
        loaded++;
    }
    fclose(f);
    process_queue();
    printf("Loaded %d log(s) from '%s'", loaded, path);
    if (skipped) printf(" (%d malformed line(s) skipped)", skipped);
    printf(".\n");
}

static void save_csv(void) {
    char path[LINE_LEN];
    read_line("Save to file (default saved_logs.csv): ", path, sizeof path);
    if (path[0] == '\0') strcpy(path, "saved_logs.csv");
    FILE *f = fopen(path, "w");
    if (!f) { printf("Cannot write '%s'.\n", path); return; }
    fprintf(f, "ip,username,timestamp,status\n");
    for (Log *l = head; l; l = l->next)
        fprintf(f, "%s,%s,%s,%s\n", l->ip, l->user, l->time, l->success ? "Success" : "Failed");
    fclose(f);
    printf("Saved %d log(s) to '%s'.\n", log_count, path);
}

static void configure(void) {
    printf("\nCurrent rules: IP failures >= %d | account failures >= %d | IP frequency >= %d\n",
           cfg.fail_th, cfg.user_fail_th, cfg.freq_th);
    int a = read_int("New IP failure threshold (Enter to keep): ", cfg.fail_th);
    int b = read_int("New account failure threshold (Enter to keep): ", cfg.user_fail_th);
    int c = read_int("New IP frequency threshold (Enter to keep): ", cfg.freq_th);
    if (a < 1 || b < 1 || c < 1) { printf("Thresholds must be at least 1. No changes made.\n"); return; }
    cfg.fail_th = a; cfg.user_fail_th = b; cfg.freq_th = c;
    rebuild_stats();
    printf("Rules updated.\n");
}

/* ------------------------------------------------------------------ */
/* Main                                                                */
/* ------------------------------------------------------------------ */

static void cleanup(void) {
    Log *l = head;
    while (l) { Log *n = l->next; free(l); l = n; }
    while (dequeue(&pending)) { }
    bst_free(bst_root);
    ht_free(&ip_table);
    ht_free(&user_table);
    stack_free();
}

static void menu(void) {
    printf("\n================================\n");
    printf("    CYBERSHIELD LOG ANALYZER\n");
    printf("================================\n");
    printf(" 1. Add Security Log\n");
    printf(" 2. Display All Logs\n");
    printf(" 3. Search Logs by IP\n");
    printf(" 4. Analyze Login Attempts\n");
    printf(" 5. Detect Suspicious Activity\n");
    printf(" 6. Display Top Active IPs\n");
    printf(" 7. Generate Security Report\n");
    printf(" 8. Delete a Log\n");
    printf(" 9. Load Logs from CSV\n");
    printf("10. Save Logs to CSV\n");
    printf("11. Recent Events (stack)\n");
    printf("12. Configure Detection Rules\n");
    printf(" 0. Exit\n");
}

int main(void) {
    for (;;) {
        menu();
        int choice = read_int("\nEnter your choice: ", -1);
        switch (choice) {
            case 1:  add_log(); break;
            case 2:  display_logs(); break;
            case 3:  search_by_ip(); break;
            case 4:  analyze_logins(); break;
            case 5:  detect_suspicious(); break;
            case 6:  display_top_ips(); break;
            case 7:  generate_report(); break;
            case 8:  delete_log(); break;
            case 9:  load_csv(); break;
            case 10: save_csv(); break;
            case 11: show_recent(); break;
            case 12: configure(); break;
            case 0:  cleanup(); printf("Goodbye.\n"); return 0;
            default: printf("Invalid choice.\n");
        }
    }
}
