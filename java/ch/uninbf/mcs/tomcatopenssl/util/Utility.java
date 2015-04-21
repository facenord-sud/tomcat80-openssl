/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ch.uninbf.mcs.tomcatopenssl.util;

/**
 *
 * @author Numa de Montmollin <numa.demontmollin@unifr.ch>
 */
public class Utility {
    public static <T extends Object> T checkNotNull(T object) {
        if(object == null)
            throw new NullPointerException("Cannot be null");
        return object;
    }
}
