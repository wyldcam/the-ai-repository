package info.tAIR.tAIRApp;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;

public class ContributorActivity extends Activity {
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        
        setContentView(R.layout.contributors);
               final Button button01 = (Button)
               findViewById(R.id.Button01);
               button01.setOnClickListener(new OnClickListener() {
                   public void onClick(View v) {
                        //Perform action on click
                   	 Uri uri = Uri.parse("http://www.tAIIC.com");
                   	 Intent intent = new Intent(Intent.ACTION_VIEW, uri);
                   	 startActivity(intent);
                   }
               });
                 
               final Button button02 = (Button)
               findViewById(R.id.Button02);
               button02.setOnClickListener(new OnClickListener() {
                   public void onClick(View v) {
                        //Perform action on click
                   	 Uri uri = Uri.parse("http://sites.jsoft.com/rm/home");
                   	 Intent intent = new Intent(Intent.ACTION_VIEW, uri);
                   	 startActivity(intent);
                   }
               });
                
               final Button button03 = (Button)
               findViewById(R.id.Button03);
               button03.setOnClickListener(new OnClickListener() {
                   public void onClick(View v) {
                        //Perform action on click
                   	 Uri uri = Uri.parse("http://www.suavestudio.com/");
                   	 Intent intent = new Intent(Intent.ACTION_VIEW, uri);
                   	 startActivity(intent);
                   }
               });
                   
               final Button button04 = (Button)
               findViewById(R.id.Button04);
               button04.setOnClickListener(new OnClickListener() {
                   public void onClick(View v) {
                        //Perform action on click
                	   finish();
                   }
               });
     }
}
