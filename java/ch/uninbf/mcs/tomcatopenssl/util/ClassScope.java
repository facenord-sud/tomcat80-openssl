/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ch.uninbf.mcs.tomcatopenssl.util;

import java.util.Vector;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

/**
 *
 * @author Numa de Montmollin <numa.demontmollin@unifr.ch>
 */
public class ClassScope {

        private static java.lang.reflect.Field LIBRARIES;
        private static final Log log = LogFactory.getLog(ClassScope.class);

        static {
            try {
                LIBRARIES = ClassLoader.class.getDeclaredField("loadedLibraryNames");
                LIBRARIES.setAccessible(true);
            } catch (NoSuchFieldException ex) {
                log.error("no such filed: " + ex);
            } catch (SecurityException ex) {
                log.error("Security exception: " + ex);
            }

        }

        public static String[] getLoadedLibraries(final ClassLoader loader) throws IllegalArgumentException, IllegalAccessException {
            final Vector<String> libraries = (Vector<String>) LIBRARIES.get(loader);
            return libraries.toArray(new String[]{});
        }
        
        public static String getLoadedLibrariesStr(final ClassLoader loader) throws IllegalArgumentException, IllegalAccessException {
            String libs = "";
            for(String lib : getLoadedLibraries(loader)) {
                libs = libs + ", " + lib;
            }
            return libs;
        }
    }
