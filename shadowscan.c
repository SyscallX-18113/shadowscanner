#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <unistd.h>
#include <time.h>

#define TOR_PROXY "socks5://127.0.0.1:9050"
#define USER_AGENT "EducationalDNS/1.0"
#define RESULTS_FILE "found_subdomains.txt"
#define REQUESTS_PER_MINUTE 12     // Conservative rate limit
#define MIN_DELAY_MS 4000          // 4 seconds minimum
#define MAX_DELAY_MS 8000          // 8 seconds maximum
#define MAX_WORDLIST_SIZE 100000   // Max 100K words
#define DEFAULT_WORDLIST "common_subdomains.txt"

#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[1;31m"
#define COLOR_GREEN   "\033[1;32m"
#define COLOR_YELLOW  "\033[1;33m"
#define COLOR_BLUE    "\033[1;34m"
#define COLOR_MAGENTA "\033[1;35m"
#define COLOR_CYAN    "\033[1;36m"
#define COLOR_WHITE   "\033[1;37m"
#define LIGHT_RED     "\033[91m"


typedef struct {
    char *data;
    size_t size;
} ResponseBuffer;

typedef struct {
    char subdomain[256];
    int found;
    char ip[46];
    int http_status;
} SubdomainResult;


SubdomainResult *results = NULL;
int result_count = 0;
int total_requests_made = 0;
time_t scan_start_time;
char **wordlist = NULL;
int wordlist_size = 0;


void print_banner();
int load_wordlist(const char *filename);
void rate_limit(int request_num);
size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp);
void add_result(const char *subdomain, int found, const char *ip, int http_status);
void save_results();
int check_tor_connection();
void query_certificate_transparency(const char *domain);
void scan_with_wordlist(const char *domain);
void print_summary();
void free_resources();


void print_banner() {

    printf(LIGHT_RED);
    printf("\t                                                             \n");
    printf("\t                                                             \n");
    printf("\t                                                             \n");
    printf("\t        .... NO! ...                  ... MNO! ...           \n");
    printf("\t       ..... MNO!! ...................... MNNOO! ...         \n");
    printf("\t     ..... MMNO! ......................... MNNOO!! .         \n");
    printf("\t    ..... MNOONNOO!   MMMMMMMMMMPPPOII!   MNNO!!!! .         \n");
    printf("\t     ... !O! NNO! MMMMMMMMMMMMMPPPOOOII!! NO! ....           \n");
    printf("\t        ...... ! MMMMMMMMMMMMMPPPPOOOOIII! ! ...             \n");
    printf("\t       ........ MMMMMMMMMMMMPPPPPOOOOOOII!! .....            \n");
    printf("\t       ........ MMMMMOOOOOOPPPPPPPPOOOOMII! ...              \n");
    printf("\t        ....... MMMMM..    OPPMMP    .,OMI! ....             \n");
    printf("\t         ...... MMMM::   o.,OPMP,.o   ::I!! ...              \n");
    printf("\t             .... NNM:::.,,OOPM!P,.::::!! ....               \n");
    printf("\t              .. MMNNNNNOOOOPMO!!IIPPO!!O! .....             \n");
    printf("\t             ... MMMMMNNNNOO:!!:!!IPPPPOO! ....              \n");
    printf("\t              ...... MMMONNMMNNNIIIOO!..........             \n");
    printf("\t           ....... MN MOMMMNNNIIIIIO! OO ..........          \n");
    printf("\t        ......... MNO! IiiiiiiiiiiiI OOOO ...........        \n");
    printf("\t      ...... NNN.MNO! . O!!!!!!!!!O . OONO NO! ........      \n");
    printf("\t       .... MNNNNNO! ...OOOOOOOOOOO .  MMNNON!........       \n");
    printf("\t       ...... MNNNNO! .. PPPPPPPPP .. MMNON!........         \n");
    printf("\t          ...... OO! ................. ON! .......           \n");
    printf("\t             ................................                \n");
    printf("\t                                                             \n");
    printf("\t                    SyscallX-18113                          \n");
    printf("\n");
    printf("\n");
    printf("\n%s", COLOR_CYAN);
    printf("    ╔════════════════════════════════════════════════════╗\n");
    printf("    ║                 SHADOW SCANNER                     ║\n");
    printf("    ║               with Wordlist Support                ║\n");
    printf("    ║            Rate Limited: %d reqs/minute            ║\n", REQUESTS_PER_MINUTE);
    printf("    ╚════════════════════════════════════════════════════╝\n");
    printf("%s\n", COLOR_RESET);
}


int load_wordlist(const char *filename) {
    printf("%s[*] Loading wordlist: %s%s\n", COLOR_YELLOW, filename, COLOR_RESET);
    
    FILE *file = fopen(filename, "r");
    if(!file) {
        printf(COLOR_RED "[!] Cannot open wordlist: %s\n" COLOR_RESET, filename);
        
      
        printf("%s[*] Creating default wordlist...%s\n", COLOR_YELLOW, COLOR_RESET);
        file = fopen(DEFAULT_WORDLIST, "w");
        if(file) {
          
            const char *default_words[] = {
                "www", "mail", "webmail", "smtp", "pop", "imap", "ftp",
                "api", "dev", "test", "staging", "prod", "beta", "alpha",
                "admin", "dashboard", "portal", "login", "secure", "auth",
                "blog", "news", "forum", "community", "support", "help",
                "shop", "store", "cart", "payment", "checkout",
                "app", "mobile", "m", "cdn", "static", "assets", "media",
                "docs", "wiki", "status", "monitor", "metrics", "stats",
                "git", "svn", "jenkins", "ci", "build", "deploy",
                "db", "sql", "mysql", "postgres", "mongo", "redis",
                "vpn", "remote", "proxy", "cache", "loadbalancer",
                "internal", "intranet", "private", "local", "home",
                "mail2", "web", "ns1", "ns2", "dns", "mx", "mx1",
                "old", "new", "legacy", "archive", "backup",
                "cloud", "aws", "azure", "google", "digitalocean",
                "test1", "test2", "demo", "stage", "preprod",
                "secure2", "admin2", "portal2", "web2", "app2",
                NULL
            };
            
            for(int i = 0; default_words[i] != NULL; i++) {
                fprintf(file, "%s\n", default_words[i]);
            }
            fclose(file);
            
            printf(COLOR_GREEN "[✓] Created default wordlist: %s\n" COLOR_RESET, DEFAULT_WORDLIST);
            printf("%s[*] Contains %d common subdomain patterns%s\n", 
                   COLOR_BLUE, sizeof(default_words)/sizeof(default_words[0]) - 1, COLOR_RESET);
            
            
            file = fopen(DEFAULT_WORDLIST, "r");
        }
        
        if(!file) {
            printf(COLOR_RED "[!] Could not create or open wordlist\n" COLOR_RESET);
            return 0;
        }
    }
    
    
    char buffer[256];
    int count = 0;
    while(fgets(buffer, sizeof(buffer), file)) {
        count++;
    }
    
    if(count == 0) {
        printf(COLOR_RED "[!] Wordlist is empty\n" COLOR_RESET);
        fclose(file);
        return 0;
    }
    
    
    wordlist = malloc(count * sizeof(char*));
    if(!wordlist) {
        printf(COLOR_RED "[!] Memory allocation failed\n" COLOR_RESET);
        fclose(file);
        return 0;
    }
    
    
    rewind(file);
    int i = 0;
    while(fgets(buffer, sizeof(buffer), file) && i < count) {
        
        buffer[strcspn(buffer, "\n")] = 0;
        
        
        if(strlen(buffer) == 0 || buffer[0] == '#') {
            continue;
        }
        
        wordlist[i] = strdup(buffer);
        if(!wordlist[i]) {
            printf(COLOR_RED "[!] Failed to duplicate string\n" COLOR_RESET);
            fclose(file);
            return 0;
        }
        i++;
    }
    
    wordlist_size = i;
    fclose(file);
    
    printf(COLOR_GREEN "[✓] Loaded %d words from wordlist\n" COLOR_RESET, wordlist_size);
    return 1;
}


void rate_limit(int request_num) {
    total_requests_made++;
    
    
    int base_delay_ms = (60 * 1000) / REQUESTS_PER_MINUTE;
    
    
    int jitter = (base_delay_ms * 25) / 100;
    int actual_delay_ms = base_delay_ms + (rand() % (2 * jitter)) - jitter;
    
    
    if(actual_delay_ms < MIN_DELAY_MS) actual_delay_ms = MIN_DELAY_MS;
    if(actual_delay_ms > MAX_DELAY_MS) actual_delay_ms = MAX_DELAY_MS;
    
 
    printf("%s[~] Rate limit: %d.%d sec (req #%d)%s\n", 
           COLOR_BLUE, 
           actual_delay_ms / 1000,
           (actual_delay_ms % 1000) / 100,
           request_num,
           COLOR_RESET);
    

    time_t now = time(NULL);
    int elapsed = (int)difftime(now, scan_start_time);
    if(elapsed > 0) {
        float current_rate = (total_requests_made * 60.0) / elapsed;
        printf("%s[*] Current rate: %.1f reqs/min%s\n", 
               COLOR_YELLOW, current_rate, COLOR_RESET);
    }
    
  
    usleep(actual_delay_ms * 1000);
}


size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    ResponseBuffer *buf = (ResponseBuffer *)userp;
    
    char *ptr = realloc(buf->data, buf->size + realsize + 1);
    if(!ptr) return 0;
    
    buf->data = ptr;
    memcpy(&(buf->data[buf->size]), contents, realsize);
    buf->size += realsize;
    buf->data[buf->size] = 0;
    
    return realsize;
}


void add_result(const char *subdomain, int found, const char *ip, int http_status) {
    results = realloc(results, (result_count + 1) * sizeof(SubdomainResult));
    strncpy(results[result_count].subdomain, subdomain, 255);
    results[result_count].subdomain[255] = '\0';
    results[result_count].found = found;
    
    if(ip) {
        strncpy(results[result_count].ip, ip, 45);
        results[result_count].ip[45] = '\0';
    } else {
        results[result_count].ip[0] = '\0';
    }
    
    results[result_count].http_status = http_status;
    result_count++;
}


void save_results() {
    FILE *fp = fopen(RESULTS_FILE, "w");
    if(!fp) {
        printf(COLOR_RED "[!] Could not save results to file\n" COLOR_RESET);
        return;
    }
    
    fprintf(fp, "# DNS Scan Results\n");
    fprintf(fp, "# Date: %s", ctime(&(time_t){time(NULL)}));
    fprintf(fp, "# Domain: From scan\n");
    fprintf(fp, "# Wordlist size: %d words\n", wordlist_size);
    fprintf(fp, "# Rate limit: %d requests/minute\n\n", REQUESTS_PER_MINUTE);
    
    
    fprintf(fp, "SUBDOMAIN,STATUS,HTTP_CODE,IP\n");
    
    int saved = 0;
    for(int i = 0; i < result_count; i++) {
        if(results[i].found) {
            fprintf(fp, "%s,FOUND,%d,%s\n", 
                    results[i].subdomain, 
                    results[i].http_status,
                    results[i].ip[0] ? results[i].ip : "N/A");
            saved++;
        }
    }
    
    fclose(fp);
    
    if(saved > 0) {
        printf(COLOR_GREEN "\n[✓] Saved %d subdomains to: %s\n" COLOR_RESET, 
               saved, RESULTS_FILE);
    }
}


int check_tor_connection() {
    printf("%s[*] Verifying Tor connection...%s\n", COLOR_YELLOW, COLOR_RESET);
    
    CURL *curl = curl_easy_init();
    if(!curl) return 0;
    
    ResponseBuffer response = {0};
    
    curl_easy_setopt(curl, CURLOPT_URL, "https://check.torproject.org/api/ip");
    curl_easy_setopt(curl, CURLOPT_PROXY, TOR_PROXY);
    curl_easy_setopt(curl, CURLOPT_PROXYTYPE, CURLPROXY_SOCKS5);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, USER_AGENT);
    
    CURLcode res = curl_easy_perform(curl);
    
    int tor_active = 0;
    if(res == CURLE_OK && response.data) {
        if(strstr(response.data, "true") != NULL) {
            printf(COLOR_GREEN "[✓] Tor connection: ACTIVE\n" COLOR_RESET);
            tor_active = 1;
        }
    } else {
        printf(COLOR_RED "[!] Tor error: %s\n" COLOR_RESET, curl_easy_strerror(res));
    }
    
    free(response.data);
    curl_easy_cleanup(curl);
    
    if(!tor_active) {
        printf(COLOR_RED "[!] Tor not available\n" COLOR_RESET);
        printf("%s[*] Starting Tor service...%s\n", COLOR_YELLOW, COLOR_RESET);
        system("sudo systemctl start tor 2>/dev/null");
        sleep(3);
        return check_tor_connection();
    }
    
    return tor_active;
}

void query_certificate_transparency(const char *domain) {
    printf("\n%s[1] Certificate Transparency Scan%s\n", COLOR_YELLOW, COLOR_RESET);
    printf("%s[*] Querying crt.sh database...%s\n", COLOR_BLUE, COLOR_RESET);
    
    CURL *curl = curl_easy_init();
    if(!curl) return;
    
    ResponseBuffer response = {0};
    char url[512];
    snprintf(url, sizeof(url), "https://crt.sh/?q=%s&output=json", domain);
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_PROXY, TOR_PROXY);
    curl_easy_setopt(curl, CURLOPT_PROXYTYPE, CURLPROXY_SOCKS5);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, USER_AGENT);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    
    printf("%s[*] Sending request through Tor...%s\n", COLOR_BLUE, COLOR_RESET);
    
    CURLcode res = curl_easy_perform(curl);
    
    if(res == CURLE_OK && response.data) {
        printf(COLOR_GREEN "[✓] Received response (%zu bytes)\n" COLOR_RESET, response.size);
        
        char *ptr = response.data;
        int found = 0;
        
        printf("%s\n%sCertificate Transparency Results:%s\n", COLOR_WHITE,
               "════════════════════════════════════════", COLOR_RESET);
        
        while((ptr = strstr(ptr, "name_value")) != NULL) {
            ptr += 10;
            char *start = strchr(ptr, '"');
            if(!start) break;
            start++;
            
            char *end = strchr(start, '"');
            if(!end) break;
            
            char subdomain[512];
            int len = end - start;
            if(len > 0 && len < 500) {
                strncpy(subdomain, start, len);
                subdomain[len] = '\0';
                
                if(strstr(subdomain, domain)) {
                    printf(COLOR_GREEN "  ✓ %s\n" COLOR_RESET, subdomain);
                    add_result(subdomain, 1, "N/A (from cert)", 0);
                    found++;
                }
            }
            ptr = end;
        }
        
        if(found > 0) {
            printf(COLOR_GREEN "\n[✓] Found %d subdomains in certificates\n" COLOR_RESET, found);
        } else {
            printf(COLOR_RED "\n[✗] No subdomains found in certificates\n" COLOR_RESET);
        }
    } else {
        printf(COLOR_RED "[✗] Certificate query failed: %s\n" COLOR_RESET, 
               curl_easy_strerror(res));
    }
    
    free(response.data);
    curl_easy_cleanup(curl);
    
   
    rate_limit(1);
}


void scan_with_wordlist(const char *domain) {
    printf("\n%s[2] Wordlist-based Scan%s\n", COLOR_YELLOW, COLOR_RESET);
    printf("%s[*] Using %d words from wordlist%s\n", COLOR_BLUE, wordlist_size, COLOR_RESET);
    printf("%s[*] Rate limit: %d requests/minute%s\n", COLOR_BLUE, REQUESTS_PER_MINUTE, COLOR_RESET);
    
    int total_tests = wordlist_size;
    int estimated_seconds = (total_tests * 60) / REQUESTS_PER_MINUTE;
    int estimated_minutes = estimated_seconds / 60;
    
    printf("%s[*] Estimated time: %d min %d sec for %d tests%s\n", 
           COLOR_BLUE, estimated_minutes, estimated_seconds % 60, total_tests, COLOR_RESET);
    printf("%s[*] Press Ctrl+C to stop early\n%s", COLOR_YELLOW, COLOR_RESET);
    
    CURL *curl = curl_easy_init();
    if(!curl) return;
    

    curl_easy_setopt(curl, CURLOPT_PROXY, TOR_PROXY);
    curl_easy_setopt(curl, CURLOPT_PROXYTYPE, CURLPROXY_SOCKS5);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 8L);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);  // HEAD request
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, USER_AGENT);
    
    int found = 0;
    int tested = 0;
    
    for(int i = 0; i < wordlist_size; i++) {
        tested++;
        
        char subdomain[512];
        snprintf(subdomain, sizeof(subdomain), "%s.%s", wordlist[i], domain);
        
        char url[1024];
        snprintf(url, sizeof(url), "https://%s", subdomain);
        
        curl_easy_setopt(curl, CURLOPT_URL, url);
        CURLcode res = curl_easy_perform(curl);
        
        if(res == CURLE_OK) {
            long http_code = 0;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
            
            if(http_code < 400) {
                printf(COLOR_GREEN "  ✓ %-25s -> HTTP %ld\n" COLOR_RESET, 
                       wordlist[i], http_code);
                add_result(subdomain, 1, "N/A", http_code);
                found++;
            } else {
                printf(COLOR_RED "  ✗ %-25s -> HTTP %ld\n" COLOR_RESET, 
                       wordlist[i], http_code);
                add_result(subdomain, 0, "N/A", http_code);
            }
        } else {
            printf(COLOR_RED "  ✗ %-25s -> No response\n" COLOR_RESET, wordlist[i]);
            add_result(subdomain, 0, "N/A", 0);
        }
        
      
        if(i < wordlist_size - 1) {
            rate_limit(tested + 1);  
        }
        
        
        if(tested % 10 == 0) {
            time_t now = time(NULL);
            int elapsed = (int)difftime(now, scan_start_time);
            int percent = (tested * 100) / wordlist_size;
            
            printf("%s[*] Progress: %d/%d (%d%%) | Found: %d | Time: %d sec\n" COLOR_RESET,
                   COLOR_YELLOW, tested, wordlist_size, percent, found, elapsed);
        }
    }
    
    curl_easy_cleanup(curl);
    
    printf("\n%s[*] Wordlist scan completed: %d/%d tests%s\n", 
           COLOR_YELLOW, tested, wordlist_size, COLOR_RESET);
    
    if(found > 0) {
        printf(COLOR_GREEN "[✓] Found %d active subdomains via wordlist\n" COLOR_RESET, found);
    } else {
        printf(COLOR_RED "[✗] No subdomains found via wordlist\n" COLOR_RESET);
    }
}


void print_summary() {
    printf("\n%s%sSCAN SUMMARY%s\n", COLOR_CYAN,
           "════════════════════════════════════════", COLOR_RESET);
    
    int found = 0;
    for(int i = 0; i < result_count; i++) {
        if(results[i].found) found++;
    }
    
    time_t end_time = time(NULL);
    int total_seconds = (int)difftime(end_time, scan_start_time);
    int minutes = total_seconds / 60;
    int seconds = total_seconds % 60;
    
    float actual_rate = total_seconds > 0 ? (total_requests_made * 60.0) / total_seconds : 0;
    
    printf("%s[*] Total Duration:   %d min %d sec\n" COLOR_RESET, 
           COLOR_WHITE, minutes, seconds);
    printf("%s[*] Total Requests:   %d\n" COLOR_RESET, COLOR_WHITE, total_requests_made);
    printf("%s[*] Actual Rate:      %.1f reqs/min\n" COLOR_RESET, COLOR_WHITE, actual_rate);
    printf("%s[*] Target Rate:      %d reqs/min\n" COLOR_RESET, COLOR_WHITE, REQUESTS_PER_MINUTE);
    printf("%s[*] Wordlist Size:    %d words\n" COLOR_RESET, COLOR_WHITE, wordlist_size);
    printf("%s[*] Subdomains Found: %d/%d\n" COLOR_RESET, COLOR_WHITE, found, result_count);
    
    if(found > 0) {
        printf("\n%s%sSUCCESSFUL DISCOVERIES:%s\n", COLOR_GREEN,
               "════════════════════════════════════════", COLOR_RESET);
        
        for(int i = 0; i < result_count; i++) {
            if(results[i].found) {
                if(results[i].http_status > 0) {
                    printf(COLOR_GREEN "  • %s (HTTP %d)\n" COLOR_RESET, 
                           results[i].subdomain, results[i].http_status);
                } else {
                    printf(COLOR_GREEN "  • %s (from certificate)\n" COLOR_RESET, 
                           results[i].subdomain);
                }
            }
        }
    }
}

void free_resources() {
    if(results) {
        free(results);
        results = NULL;
    }
    
    if(wordlist) {
        for(int i = 0; i < wordlist_size; i++) {
            free(wordlist[i]);
        }
        free(wordlist);
        wordlist = NULL;
        wordlist_size = 0;
    }
}


int main(int argc, char *argv[]) {
    print_banner();
    
    if(argc < 2 || argc > 3) {
        printf("%sUsage: %s <domain> [wordlist.txt]\n" COLOR_RESET, COLOR_YELLOW, argv[0]);
        printf("%sExamples:\n" COLOR_RESET, COLOR_BLUE);
        printf("  %s example.com\n", argv[0]);
        printf("  %s example.com subdomains.txt\n", argv[0]);
        printf("  %s example.com /usr/share/wordlists/subdomains.txt\n\n", argv[0]);
        
        return 1;
    }
    
    const char *domain = argv[1];
    const char *wordlist_file = (argc == 3) ? argv[2] : DEFAULT_WORDLIST;
    
    printf("%s[*] Target Domain:   %s\n" COLOR_RESET, COLOR_WHITE, domain);
    printf("%s[*] Wordlist:        %s\n" COLOR_RESET, COLOR_WHITE, wordlist_file);
    printf("%s[*] Mode:            Passive\n" COLOR_RESET, COLOR_WHITE);
    printf("%s[*] Anonymity:       Tor Network\n" COLOR_RESET, COLOR_WHITE);
    printf("%s[*] Rate Limit:      %d requests/minute\n\n" COLOR_RESET, 
           COLOR_WHITE, REQUESTS_PER_MINUTE);
    
    
    srand(time(NULL));
    scan_start_time = time(NULL);
    result_count = 0;
    total_requests_made = 0;
    
    if(!load_wordlist(wordlist_file)) {
        printf(COLOR_RED "[!] Failed to load wordlist. Exiting.\n" COLOR_RESET);
        return 1;
    }
    
    if(!check_tor_connection()) {
        printf(COLOR_RED "[!] Tor connection failed. Exiting.\n" COLOR_RESET);
        free_resources();
        return 1;
    }
    

    printf("%s[*] Initializing scan...\n" COLOR_RESET, COLOR_BLUE);
    sleep(2);
    
    
    query_certificate_transparency(domain);
    
   
    printf("\n%sStart wordlist scan? (y/n): " COLOR_RESET, COLOR_YELLOW);
    char response[10];
    scanf("%9s", response);
    
    if(response[0] == 'y' || response[0] == 'Y') {
        scan_with_wordlist(domain);
    } else {
        printf("%s[*] Skipping wordlist scan\n" COLOR_RESET, COLOR_YELLOW);
    }
    
    
    print_summary();
    save_results();
    
    
    printf("\n%s%sSCAN COMPLETE%s\n", COLOR_CYAN,
           "════════════════════════════════════════", COLOR_RESET);
    
    printf("%s\nNotes:\n" COLOR_RESET, COLOR_MAGENTA);
    printf("%s• All requests routed through Tor network\n" COLOR_RESET, COLOR_WHITE);
    printf("%s• Rate limits respected to avoid detection\n" COLOR_RESET, COLOR_WHITE);
    printf("%s• Results saved for learning reference\n" COLOR_RESET, COLOR_WHITE);
    printf("%s• Use knowledge responsibly and ethically\n" COLOR_RESET, COLOR_WHITE);
    
    // Cleanup
    free_resources();
    
    return 0;
}
