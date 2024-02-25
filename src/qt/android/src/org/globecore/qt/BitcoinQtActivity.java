package org.globecore.qt;

import android.os.Bundle;
import android.system.ErrnoException;
import android.system.Os;

import org.qtproject.qt5.android.bindings.QtActivity;

import java.io.File;

public class GlobeQtActivity extends QtActivity
{
    @Override
    public void onCreate(Bundle savedInstanceState)
    {
        final File globeDir = new File(getFilesDir().getAbsolutePath() + "/.globe");
        if (!globeDir.exists()) {
            globeDir.mkdir();
        }

        super.onCreate(savedInstanceState);
    }
}
