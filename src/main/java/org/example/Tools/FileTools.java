package org.example.Tools;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Simple file utilities for reading and writing raw byte arrays using absolute paths.
 */
public final class FileTools {

    /**
     * Reads the file and gives the corresponding byte sequence of it.
     * @param absPathFile Absolute path of the file to read.
     * @return Byte sequence of the content of the file
     * @throws IOException Error thrown for Input Output exceptions
     */
    public static byte[] readFile(String absPathFile) throws IOException {
        try{
            // Llegeix tot el contingut del fitxer com a bytes
            byte[] data = Files.readAllBytes(Path.of(absPathFile));

            return data;
        } catch (IOException ex){
            throw new IOException("ERROR: no es troba el fitxer o no es pot llegir");
        }
    }

    /**
     * Writes the content given to an absolute path of a file. If the file does not exist, it creates it.
     * Otherwise, overwrites the content of it.
     * @param absPathFile Absolute path of the file to write
     * @param content Data to write
     * @throws IOException Error thrown for Input Output exceptions
     */
    public static void writeFile(String absPathFile, byte[] content) throws IOException {
        try{
            Files.write(Path.of(absPathFile), content);
        } catch (IOException ex){
            throw new IOException("ERROR: no s'ha pogut desar el contingut");
        }
    }
}
