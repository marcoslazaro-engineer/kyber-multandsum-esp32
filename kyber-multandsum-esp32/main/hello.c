#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_log.h"

#include "params.h"   
#include "ntt.h"      
#include "poly.h"     
#include "polyvec.h"
#include "indcpa.h"
#include "cbd.h"
#include "symmetric.h"
#include "randombytes.h"

#define TAG "KYBER_MATVEC"

// Function to print first N coefficients of a polynomial
void print_poly_summary(const char *name, poly *p, int num_coeffs) {
    printf("%s (first %d coeffs): ", name, num_coeffs);
    for (int i = 0; i < num_coeffs && i < KYBER_N; i++) {
        printf("%d ", p->coeffs[i]);
        if ((i + 1) % 8 == 0) printf("\n");
    }
    if (num_coeffs % 8) printf("\n");
    
    // Calculate checksum for verification
    long sum = 0;
    for (int i = 0; i < KYBER_N; i++) {
        sum += p->coeffs[i];
    }
    printf("%s checksum: %ld\n\n", name, sum % KYBER_Q);
}

// Print polyvec summary
void print_polyvec_summary(const char *name, polyvec *v, int num_coeffs) {
    printf("=== %s ===\n", name);
    for (int i = 0; i < KYBER_K; i++) {
        char poly_name[32];
        snprintf(poly_name, sizeof(poly_name), "%s[%d]", name, i);
        print_poly_summary(poly_name, &v->vec[i], num_coeffs);
    }
}

// Matrix-vector multiplication: result = A * s
void matrix_vector_multiply(polyvec *result, polyvec A[KYBER_K], polyvec *s) {
    printf("Starting matrix-vector multiplication A * s...\n");
    
    for (int i = 0; i < KYBER_K; i++) {
        // result[i] = A[i] · s (dot product of row i with vector s)
        polyvec_basemul_acc_montgomery(&result->vec[i], &A[i], s);
        
        printf("Computed result row %d\n", i);
    }
    
    printf("Matrix-vector multiplication complete!\n\n");
}

// Add two polyvecs: result = a + b (remove this function, use the built-in one)

void app_main(void) {
    ESP_LOGI(TAG, "Kyber512 Matrix-Vector Multiplication Test");
    
    // Static allocation to avoid stack overflow
    static polyvec A[KYBER_K];      // Matrix A (k x k)
    static polyvec s, e, t;         // Vectors s, e, t
    static polyvec As;              // A * s result
    
    uint8_t seed[32];
    uint8_t noiseseed[32];
    
    // Generate random seeds
    randombytes(seed, 32);
    randombytes(noiseseed, 32);
    
    printf("Matrix generation seed: ");
    for (int i = 0; i < 32; i++) printf("%02X", seed[i]);
    printf("\n\n");
    
    // Step 1: Generate matrix A
    printf("=== Step 1: Generating matrix A ===\n");
    gen_matrix(A, seed, 0);
    printf("Matrix A generated successfully\n\n");
    
    // Step 2: Generate noise vectors s and e
    printf("=== Step 2: Generating noise vectors s and e ===\n");
    
    // Generate s vector
    for (int i = 0; i < KYBER_K; i++) {
        uint8_t buf[KYBER_ETA1 * KYBER_N / 4];
        kyber_shake256_prf(buf, sizeof(buf), noiseseed, i);
        poly_cbd_eta1(&s.vec[i], buf);
        poly_ntt(&s.vec[i]);  // Convert to NTT domain for multiplication
    }
    
    // Generate e vector  
    for (int i = 0; i < KYBER_K; i++) {
        uint8_t buf[KYBER_ETA1 * KYBER_N / 4];
        kyber_shake256_prf(buf, sizeof(buf), noiseseed, KYBER_K + i);
        poly_cbd_eta1(&e.vec[i], buf);
    }
    
    print_polyvec_summary("s (NTT domain)", &s, 8);
    print_polyvec_summary("e (time domain)", &e, 8);
    
    // Step 3: Matrix-vector multiplication A * s
    printf("=== Step 3: Computing A * s ===\n");
    matrix_vector_multiply(&As, A, &s);
    
    // Convert As back to time domain for addition using correct function
   for (int i = 0; i < KYBER_K; i++) {
    poly_invntt_tomont(&As.vec[i]);
    }
    print_polyvec_summary("A*s (time domain)", &As, 8);
    
    // Step 4: Compute t = A*s + e (using built-in function)
    printf("=== Step 4: Computing t = A*s + e ===\n");
    polyvec_add(&t, &As, &e);  // Use the built-in function with const parameters
    
    print_polyvec_summary("t = A*s + e", &t, 8);
    
    // Step 5: Reduce coefficients modulo q
    printf("=== Step 5: Reducing t modulo q ===\n");
    polyvec_reduce(&t);
    
    print_polyvec_summary("t (reduced mod q)", &t, 8);
    
    ESP_LOGI(TAG, "Key generation computation complete!");
    ESP_LOGI(TAG, "Public key would be: (t, rho)");
    ESP_LOGI(TAG, "Private key would be: s");
    
    // Memory usage info
    size_t free_heap = esp_get_free_heap_size();
    ESP_LOGI(TAG, "Free heap memory: %zu bytes", free_heap);
    
    while (1) {
        vTaskDelay(5000 / portTICK_PERIOD_MS);
    }
}
