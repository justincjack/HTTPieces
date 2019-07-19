/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   showbits.h
 * Author: justinjack
 *
 * Created on June 18, 2019, 11:42 AM
 */

#ifndef SHOWBITS_H
#define SHOWBITS_H

#ifdef __cplusplus
extern "C" {
#endif

    #include <stdint.h>
    #include <stdio.h>
    #include <math.h>

    /*
     * Prints the bits in a single octet
     */

    int showbits( uint8_t c );

    /*
     * Print the bits in a 32 bit integer
     * 
     */
    int show32bits( uint32_t c );

    /*
     * 
     * Prints out the bits in an array of octets
     * up to 'len' octets.
     * 
     */
    int shownbits( uint8_t *c, int len );

    /*
     * Shows a hex representation of the array of octets pointed to
     * by 'in' parameter up to 'len' octets.
     * 
     */
    void showhex( uint8_t *in, int len);
    

#ifdef __cplusplus
}
#endif

#endif /* SHOWBITS_H */

