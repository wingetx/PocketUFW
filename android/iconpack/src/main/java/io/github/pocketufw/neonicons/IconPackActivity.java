package io.github.pocketufw.neonicons;

import android.app.Activity;
import android.os.Bundle;
import android.graphics.Color;
import android.view.Gravity;
import android.widget.LinearLayout;
import android.widget.ImageView;
import android.widget.TextView;

public final class IconPackActivity extends Activity {
    @Override public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setGravity(Gravity.CENTER);
        box.setPadding(40, 40, 40, 40);
        box.setBackgroundColor(Color.rgb(18, 21, 29));
        ImageView icon = new ImageView(this);
        icon.setImageResource(R.drawable.pocketufw_neon);
        box.addView(icon, new LinearLayout.LayoutParams(192, 192));
        TextView note = new TextView(this);
        note.setText("PocketUFW Neon\n\nChoose this pack from Niagara's app icon picker. No permissions or background services.");
        note.setTextColor(Color.WHITE);
        note.setTextSize(16);
        note.setGravity(Gravity.CENTER);
        box.addView(note);
        setContentView(box);
    }
}
