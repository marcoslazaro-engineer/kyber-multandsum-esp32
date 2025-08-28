
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>

#include "esp_timer.h"
#include "driver/gpio.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "params.h"
#include "cbd.h"

#include "ntt.h"
#include "poly.h"
#include "polyvec.h"
#include "indcpa.h"
#include "symmetric.h"
#include "randombytes.h"
#include "kyber_utils.h"

#define TAG "KYBER_MATVEC"
#ifndef TRIGGER_GPIO
  #define TRIGGER_GPIO 2
#endif

static inline void trigger_init(void) {
    gpio_config_t io_conf = {
        .pin_bit_mask = 1ULL << TRIGGER_GPIO,
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE
    };
    gpio_config(&io_conf);
    gpio_set_level(TRIGGER_GPIO, 0);
}

static inline void trigger_high(void) { gpio_set_level(TRIGGER_GPIO, 1); }
static inline void trigger_low(void)  { gpio_set_level(TRIGGER_GPIO, 0); }

static void print_polyvec_short(const char *title, const polyvec *v, int first_coeffs) {
    printf("=== %s ===\n", title);
    for (int i = 0; i < KYBER_K; i++) {
        printf("%s[%d] (first %d coeffs): ", title, i, first_coeffs);
        for (int j = 0; j < first_coeffs && j < KYBER_N; j++) {
            printf("%d ", v->vec[i].coeffs[j]);
        }
        printf("\n");
    }
    printf("\n");
}

void app_main(void) {
    printf("\n--- KYBER512 Matrix-Vector (A*s + e) instrumented ---\n");

    trigger_init();

    /* Buffers (static to avoid stack issues) */
    static polyvec A[KYBER_K];      // matrix
    static polyvec s, e, As, t;     // vectors
    memset(&A, 0, sizeof(A));
    memset(&s, 0, sizeof(s));
    memset(&e, 0, sizeof(e));
    memset(&As, 0, sizeof(As));
    memset(&t, 0, sizeof(t));

    /* Seeds */
    uint8_t seed[32];
    uint8_t noiseseed[32];
    randombytes(seed, sizeof(seed));
    randombytes(noiseseed, sizeof(noiseseed));

    printf("Matrix seed: ");
    for (size_t i=0;i<sizeof(seed);i++) printf("%02X", seed[i]);
    printf("\nNoise seed : ");
    for (size_t i=0;i<sizeof(noiseseed);i++) printf("%02X", noiseseed[i]);
    printf("\n\n");

    /* ---------- Step 1: gen_matrix (A) ---------- */
    int64_t t_gen_A_start = esp_timer_get_time();
    trigger_high();
    gen_matrix(A, seed, 0);
    trigger_low();
    int64_t t_gen_A_end = esp_timer_get_time();
    printf("# Time gen_matrix (us): %" PRId64 "\n", t_gen_A_end - t_gen_A_start);

    /* ---------- Step 2: generate s and NTT(s) ---------- */
    printf("Generating secret vector s and converting to NTT domain...\n");
    int64_t t_ntt_s_start = esp_timer_get_time();
    for (int i = 0; i < KYBER_K; i++) {
        uint8_t buf[KYBER_ETA1 * KYBER_N / 4];
        kyber_shake256_prf(buf, sizeof(buf), noiseseed, i);
        poly_cbd_eta1(&s.vec[i], buf);
        /* NTT conversion per-poly with local trigger pulse for trace alignment */
        trigger_high();
        poly_ntt(&s.vec[i]);
        trigger_low();
    }
    int64_t t_ntt_s_end = esp_timer_get_time();
    printf("# Time poly_ntt(s) total (us): %" PRId64 "\n", t_ntt_s_end - t_ntt_s_start);

    /* ---------- Step 3: generate e (time domain) ---------- */
    int64_t t_gen_e_start = esp_timer_get_time();
    for (int i = 0; i < KYBER_K; i++) {
        uint8_t buf[KYBER_ETA1 * KYBER_N / 4];
        kyber_shake256_prf(buf, sizeof(buf), noiseseed, KYBER_K + i);
        poly_cbd_eta1(&e.vec[i], buf);
    }
    int64_t t_gen_e_end = esp_timer_get_time();
    printf("# Time generate e (us): %" PRId64 "\n", t_gen_e_end - t_gen_e_start);

    /* Short summaries for debug/verification */
    print_polyvec_short("s (NTT domain)", &s, 8);
    print_polyvec_short("e (time domain)", &e, 8);

    /* ---------- Step 4: compute A * s in NTT domain ---------- */
    printf("Computing A * s (NTT domain) with per-row trigger pulses...\n");
    int64_t t_matmul_start = esp_timer_get_time();
    for (int i = 0; i < KYBER_K; i++) {
        /* Each row: accumulate basemul over K polys into As.vec[i] */
        /* Trigger around the whole row computation for clear scope window */
        trigger_high();
        /* polyvec_basemul_acc_montgomery(acc, &A[i], &s) usually accumulates A[i] dot s */
        polyvec_basemul_acc_montgomery(&As.vec[i], &A[i], &s);
        trigger_low();
    }
    int64_t t_matmul_end = esp_timer_get_time();
    printf("# Time mat-vec basemul (us): %" PRId64 "\n", t_matmul_end - t_matmul_start);

    /* ---------- Step 5: invNTT(As) to time domain ---------- */
    printf("Applying inverse NTT to A*s...\n");
    int64_t t_invntt_start = esp_timer_get_time();
    for (int i = 0; i < KYBER_K; i++) {
        trigger_high();
        poly_invntt_tomont(&As.vec[i]);
        trigger_low();
    }
    int64_t t_invntt_end = esp_timer_get_time();
    printf("# Time invNTT(As) total (us): %" PRId64 "\n", t_invntt_end - t_invntt_start);

    print_polyvec_short("A*s (time domain)", &As, 8);

    /* ---------- Step 6: t = A*s + e ---------- */
    printf("Computing t = A*s + e (vector add) ...\n");
    int64_t t_add_start = esp_timer_get_time();
    trigger_high();
    polyvec_add(&t, &As, &e);
    trigger_low();
    int64_t t_add_end = esp_timer_get_time();
    printf("# Time add (us): %" PRId64 "\n", t_add_end - t_add_start);

    /* ---------- Step 7: reduce coefficients ---------- */
    printf("Reducing t coefficients modulo q ...\n");
    int64_t t_reduce_start = esp_timer_get_time();
    trigger_high();
    polyvec_reduce(&t);
    trigger_low();
    int64_t t_reduce_end = esp_timer_get_time();
    printf("# Time reduce (us): %" PRId64 "\n", t_reduce_end - t_reduce_start);

    /* ---------- Final summary ---------- */
    int64_t total_us = (t_reduce_end - t_gen_A_start);
    printf("\n# Total time A*s+e pipeline (us): %" PRId64 "\n\n", total_us);

    print_polyvec_short("t = A*s + e (reduced)", &t, 8);

    size_t free_heap = esp_get_free_heap_size();
    printf("# Free heap: %zu bytes\n", free_heap);

    /* Keep running so scope/DAQ can be stopped manually after tracing */
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
