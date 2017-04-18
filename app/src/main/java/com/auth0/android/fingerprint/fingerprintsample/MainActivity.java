package com.auth0.android.fingerprint.fingerprintsample;

import android.os.Bundle;
import android.support.annotation.Nullable;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

public class MainActivity extends AppCompatActivity implements View.OnClickListener, FingerprintAuth.Callback {

    private FingerprintAuth fingerprintAuth;
    private TextView textSensorStatus;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Button buttonCancel = (Button) findViewById(R.id.buttonCancel);
        Button buttonEncrypt = (Button) findViewById(R.id.buttonEncrypt);
        Button buttonDecrypt = (Button) findViewById(R.id.buttonDecrypt);
        buttonCancel.setOnClickListener(this);
        buttonEncrypt.setOnClickListener(this);
        buttonDecrypt.setOnClickListener(this);
        textSensorStatus = (TextView) findViewById(R.id.textSensorStatus);

        fingerprintAuth = new FingerprintAuth(this, this, "alias");
    }

    @Override
    public void onClick(View v) {
        int id = v.getId();
        switch (id) {
            case R.id.buttonCancel:
                fingerprintAuth.cancelAuthentication();
                break;
            case R.id.buttonEncrypt:
                fingerprintAuth.register("My secret", true);
                Toast.makeText(this, "Registered!", Toast.LENGTH_SHORT).show();
                break;
            case R.id.buttonDecrypt:
                updateSensorStatus(true);
                fingerprintAuth.authenticate();
                break;
        }
    }

    @Override
    public void onAuthenticated(@Nullable String secret) {
        updateSensorStatus(false);
        Toast.makeText(this, "Authenticated. Secret is: " + secret, Toast.LENGTH_SHORT).show();
    }

    @Override
    public void onCanceled() {
        updateSensorStatus(false);
        Toast.makeText(this, "Cancelled", Toast.LENGTH_SHORT).show();
    }

    @Override
    public void onError(Throwable error) {
        updateSensorStatus(false);
        Toast.makeText(this, "Error: " + error, Toast.LENGTH_SHORT).show();
    }

    private void updateSensorStatus(boolean scanning) {
        textSensorStatus.setText(scanning ? "Sensor status: ON" : "Sensor status: OFF");
    }
}
