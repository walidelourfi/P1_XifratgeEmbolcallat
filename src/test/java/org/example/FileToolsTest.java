package org.example;

import junit.framework.TestCase;
import org.example.Tools.FileTools;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Tests for FileTools read/write helpers.
 */
public class FileToolsTest extends TestCase {

    public void testWriteAndReadRoundTrip() throws IOException {
        Path temp = Files.createTempFile("p1walid", ".bin");
        try {
            byte[] content = new byte[]{0,1,2,3,4,5,6,7,8,9};
            FileTools.writeFile(temp.toString(), content);
            byte[] read = FileTools.readFile(temp.toString());
            assertEquals(content.length, read.length);
            for (int i = 0; i < content.length; i++) {
                assertEquals(content[i], read[i]);
            }
        } finally {
            Files.deleteIfExists(temp);
        }
    }
}
