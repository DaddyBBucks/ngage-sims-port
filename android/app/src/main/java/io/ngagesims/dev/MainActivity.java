package io.ngagesims.dev;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;
import com.chaquo.python.PyObject;
import com.chaquo.python.Python;
import com.chaquo.python.android.AndroidPlatform;

public final class MainActivity extends Activity {
    private TextView status;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        setContentView(R.layout.activity_main);
        status = findViewById(R.id.status);
        status.setText("Gate B: press test after the pinned Unicorn dependency is prepared.");
        findViewById(R.id.probe).setOnClickListener(v -> runProbe());
    }

    private void runProbe() {
        try {
            System.loadLibrary("unicorn");
            if (!Python.isStarted()) Python.start(new AndroidPlatform(this));
            PyObject result = Python.getInstance()
                    .getModule("runtime_probe").callAttr("probe");
            status.setText(result.toString());
        } catch (Throwable t) {
            status.setText("Gate B failed: " + t.getClass().getSimpleName()
                    + ": " + t.getMessage());
        }
    }
}
