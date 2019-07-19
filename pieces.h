/* 
 * File:   pieces.h
 * Author: justinjack
 *
 * Created on July 9, 2019, 12:50 PM
 */

#ifndef PIECES_H
#define PIECES_H

#include <stdio.h>
#include <stdint.h>
#include <memory.h>
#include <string.h>
#include <sys/stat.h>
#include <signal.h>
#include <zlib.h>
#include <errno.h>
#include "debug.h"
#include "mutex.h"



#define PIECES_UNABLE_TO_LOAD_FILE              -3
#define PIECES_OUT_OF_MEMORY                    -2
#define PIECES_FILE_NOT_FOUND                   -1
#define PIECES_SUCCESS                           1
#define PIECES_NO_MAP                            0




static int PIECES_BITSIZE                       = (sizeof(void *)*8);   /*
                                                                         * Get the CPU registers' bit-size for hashing AQAP
                                                                         **


/****************************************************************************************************************************************/

/** FORWARD DECS ************************************************************************************************************************/

typedef struct _pieces_map_ PIECES_MAP, *PPIECES_MAP;










/****************************************************************************************************************************************/

/** STRUCTS *****************************************************************************************************************************/


/* PIECES_MAP, *PPIECES_MAP
 * 
 * This struct acts as a flat hashmap array and linked-list.  It gets built
 * while loading all the HTTPieces/included files.  It maps out how to compile
 * the final resource and puts it together watching for any potential infinite
 * recursion.
 *  
 **/
struct _pieces_map_ {
    
    const char                  *filename;                          /* The path to and name of the loaded file.
                                                                     * 
                                                                     **/
    
    char                        *data;                              /*
                                                                     * File contents from "filename".
                                                                     * 
                                                                     **/
    
    size_t                      file_len;                           /*
                                                                     * The length of the data buffered in "data" in
                                                                     * bytes.
                                                                     * 
                                                                     **/
    
    uint8_t                     *compressed;                        /*
                                                                     * Only valid where "branch == 0", this is the compressed
                                                                     * (gzipped) version of the compiled resource is stored.
                                                                     * 
                                                                     * It gets populated by either: pieces_get_resource(), 
                                                                     * or the pieces_stat_checker() thread if it determines
                                                                     * that it needs to do so.
                                                                     * 
                                                                     **/
    
    
    size_t                      compiled_size;                      /*
                                                                     * The buffer size needed to hold the compiled version of
                                                                     * this resource and its dependencies.
                                                                     * 
                                                                     **/
    
    struct stat                 stats;                              /*
                                                                     * The last info from "stat()" for this file.
                                                                     * 
                                                                     **/
    
    
    uint64_t                    branch;                             /*
                                                                     * An unique integer identifier assigned to each
                                                                     * new load-directive branch starting from "filename"
                                                                     * 
                                                                     **/
    
    uint64_t                    recursion_level;                    /*
                                                                     * The level of recursion we've reached at the time
                                                                     * that this file's reference was found in the code.
                                                                     * 
                                                                     * If this file's name comes up again twice:
                                                                     * 
                                                                     *      1. If it is in a higher recursion level,
                                                                     *         but a different path, then it's okay.
                                                                     * 
                                                                     *      2. Higher recursion level but same path, not
                                                                     *         okay.
                                                                     * 
                                                                     **/
    
    PPIECES_MAP                 prev, next, head;                   /*
                                                                     * Linked-List traversal
                                                                     * 
                                                                     **/
    
};




static PPIECES_MAP              *pieces_map                 = 0;    /*
                                                                     * An array for holding our mapped filenames for resource compilation.
                                                                     * 
                                                                     **/

static size_t                   pieces_map_arr_size         = 1000; /*
                                                                     * We'll start with 1000.  Hopefully we won't need that many, but ya
                                                                     * never know.  I'd like to avoid calling "pieces_remap()" to keep 
                                                                     * overall service time lickety-split!
                                                                     * 
                                                                     **/ 



static PMUTEX                   pieces_mutex                = 0;     /*
                                                                      * Protect our "pieces_map"
                                                                      * 
                                                                      **/


static pthread_t                p_stat_checker;                     /*
                                                                     * Thread ID for stat checker.
                                                                     * 
                                                                     **/

static int                      p_stat_checker_run          = 0;    /*
                                                                     * Flag letting the stat checker that it's supposed to be alive and
                                                                     * running.  This will get set to ZERO when it's time for it to die.
                                                                     * 
                                                                     **/


#ifdef __cplusplus
extern "C" {
#endif
    
    /****************************************************************************************************************************************/

    /** PUBLIC API **************************************************************************************************************************/

    /*!
     * \brief This function takes the path/filename of a requested resource.  It loads that file
     *        and starts walking that file and any HTTPieces - Includes it finds and loads them,
     *        maps them and compresses them for service.  It also watches them in the background and
     *        if any changes are made to any of the composite files, it will rebuild the entire 
     *        resource so it will be available much faster the next time.
     * 
     *        It will NOT compress CGI / script files.  That will have to be done further upstream.
     *        Here, we WILL cache them and make sure the cache is current and valid, but we can't
     *        have them already compressed because they may have to be run through CGI first..
     * 
     * \param filename                                  - The PATH TO and FILENAME OF (relative to the 
     *                                                    configured document root) the resource to
     *                                                    load and compile.
     * 
     * \param outbuflen                                 - A pointer to a buffer (of type size_t) that
     *                                                    receives the size in octets of the buffer to
     *                                                    be returned.
     *        
     * \return On Success                               - A buffer containing the compiled resource to
     *                                                    be served.
     * 
     * \return On Failure                               - NULL (ZERO)  "errno" will be set to one of the following:
     *  
     *                                                      * PIECES_FILE_NOT_FOUND         ( -1 )
     * 
     *                                                      * PIECES_OUT_OF_MEMORY          ( -2 )
     * 
     *                                                      * PIECES_UNABLE_TO_LOAD_FILE    ( -3 )
     *        
     */
    char                        *pieces_get_resource( const char *filename, size_t *outbuflen, int *is_compressed);
    
    /*!
     * \brief Initializes the PIECES environment.  Can be called explicitly to prepare
     *        thing ahead of time, or it will be called internally if any other functions
     *        are used and it hasn't been called yet.
     * 
     * \param document_root            - MAY BE NULL!  But if it is passed, pieces_init() will
     *                                   go ahead (in the background) start indexing, compiling
     *                                   and compressing (not CGI/scripts) files for quicker service
     *                                   later on.
     * 
     * \return On Success              - PIECES_SUCCESS
     * 
     * \return On Failure              - PIECES_UNABLE_TO_LOAD_FILE  ( -3 )
     * 
     *                                   PIECES_OUT_OF_MEMORY        ( -2 )
     * 
     *                                   PIECES_FILE_NOT_FOUND       ( -1 )
     * 
     * 
     * 
     **/
    int                         pieces_init( char *document_root ); 
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    /****************************************************************************************************************************************/

    /** SEMI-PRIVATE INTERNAL FUNCTIONS *****************************************************************************************************/
    
    /*!
     * \brief Our signal handler for pieces_stat_checker() thread
     * 
     * \param s                         - The signal number
     * 
     * \return Nothing
     * 
     **/
    void pieces_signals( int s );
    
    /*!
     * \brief Quick function to hash our string to get it's array index
     * 
     * \param ptr                           - A pointer to a buffer containing
     *                                        the string (in this case a filename)
     *                                        to hash.
     * 
     * \return The index apropos to our PIECES_MAP
     */
    inline uint64_t             p_index( const char *ptr );
    


    /*!
     * \brief This function doubles the size of the "pieces_map" array and
     *        re-indexes all the entries.  Hopefully we won't have to call
     *        this too often :\
     * 
     * \param None
     * 
     * \return On Success  ( > 0 )          - The new array count
     * 
     * \return On Failure                   - The old map (if any) will still 
     *                                        in place and one of the 
     *                                        following errors will be returned:
     * 
     *                                           PIECES_UNABLE_TO_LOAD_FILE     ( -3 )
     * 
     *                                           PIECES_OUT_OF_MEMORY           ( -2 )
     * 
     *                                           PIECES_FILE_NOT_FOUND          ( -1 )
     * 
     *                                           PIECES_NO_MAP                  (  0 )
     * 
     * 
     **/
    inline int64_t              pieces_remap( void );
    
    
    /*!
     * \brief This function inserts a pointer to a PIECES_MAP structure
     *        into the "pieces_map"
     * 
     * \param pm                            - A pointer to a prepared PIECES_MAP
     *                                        structure prepared by 
     *                                        "pieces_load_file()"
     * 
     * 
     * \return On Success                   - The number of elements mapped
     * 
     * \return On Failure                   
     *                                           PIECES_UNABLE_TO_LOAD_FILE     ( -3 )
     * 
     *                                           PIECES_OUT_OF_MEMORY           ( -2 )
     * 
     *                                           PIECES_FILE_NOT_FOUND          ( -1 )
     * 
     *                                           PIECES_NO_MAP                  (  0 )
     * 
     * 
     **/
    inline int64_t              pieces_index( PPIECES_MAP *pm );
    
    
    /*!
     * \brief Loads a single file into a memory buffer.
     * 
     * \param file                      - A pointer to the filename that is to
     *                                    be read.
     * 
     * \return On Success  ( > 0 )      - The index (in "pieces_map") of the 
     *                                    entry for the loaded "file" parameter.
     * 
     * \return On Failure               - PIECES_FILE_NOT_FOUND         ( -1 )
     *                      
     *                                  - PIECES_OUT_OF_MEMORY          ( -2 )
     * 
     *                                  - PIECES_UNABLE_TO_LOAD_FILE    ( -3 )
     */
    int64_t                     pieces_load_file( const char *file );
    
    /*!
     * \brief This thread runs in the background to reload any files that have
     *        been modified by developers or anything else that could change 
     *        their status.
     * 
     * \param void pointer
     * 
     * \return void pointer
     */
    void                        *pieces_stat_checker( void * );

    
    


    

#ifdef __cplusplus
}
#endif

#endif /* PIECES_H */

