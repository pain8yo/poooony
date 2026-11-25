package com.pain8yo.mlpsaveeditor;

import android.app.*;
import android.os.*;
import android.content.*;
import android.net.Uri;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.view.*;
import android.widget.*;
import org.w3c.dom.*;
import javax.xml.parsers.*;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.nio.*;
import java.util.zip.*;

public class MainActivity extends Activity {
  static final int PICK_SAVE=1, PICK_DB=2, CREATE_OUT=3;
  byte[] saveBytes; String gluid; EditText bits,gems; TextView status;
  @Override public void onCreate(Bundle b){super.onCreate(b);
    LinearLayout root=new LinearLayout(this); root.setOrientation(1); root.setPadding(28,28,28,28);
    TextView title=new TextView(this); title.setText("MLP Save Editor"); title.setTextSize(24); root.addView(title);
    Button s=button("1. Выбрать mlp_save_prime.dat"); root.addView(s); s.setOnClickListener(v->pick(PICK_SAVE,"application/octet-stream"));
    Button d=button("2. Выбрать gameloft_sharing"); root.addView(d); d.setOnClickListener(v->pick(PICK_DB,"*/*"));
    TextView l=new TextView(this); l.setText("Bits"); root.addView(l); bits=new EditText(this); bits.setInputType(2); bits.setText("1000000"); root.addView(bits);
    TextView g=new TextView(this); g.setText("Gems"); root.addView(g); gems=new EditText(this); gems.setInputType(2); gems.setText("10000"); root.addView(gems);
    Button go=button("3. Изменить валюту и сохранить файл"); root.addView(go); go.setOnClickListener(v->edit());
    status=new TextView(this); status.setPadding(0,24,0,0); root.addView(status); setContentView(root);
  }
  Button button(String t){Button b=new Button(this);b.setText(t);return b;}
  void pick(int req,String type){Intent i=new Intent(Intent.ACTION_OPEN_DOCUMENT);i.setType(type);i.addCategory(Intent.CATEGORY_OPENABLE);startActivityForResult(i,req);}
  byte[] read(Uri u)throws Exception{ByteArrayOutputStream o=new ByteArrayOutputStream();try(InputStream in=getContentResolver().openInputStream(u)){byte[] b=new byte[8192];int n;while((n=in.read(b))>0)o.write(b,0,n);}return o.toByteArray();}
  @Override protected void onActivityResult(int r,int c,Intent d){super.onActivityResult(r,c,d);if(c!=RESULT_OK||d==null)return;try{
    if(r==PICK_SAVE){saveBytes=read(d.getData());status.setText("Сохранение загружено: "+saveBytes.length+" байт");}
    if(r==PICK_DB){File f=new File(getCacheDir(),"sharing.db");try(FileOutputStream o=new FileOutputStream(f)){o.write(read(d.getData()));}
      SQLiteDatabase db=SQLiteDatabase.openDatabase(f.getAbsolutePath(),null,SQLiteDatabase.OPEN_READONLY);
      Cursor q=db.rawQuery("SELECT value FROM glshare WHERE key=?",new String[]{"ANMP.GloftPOHM_GAIA_ENC_KEY_GLUID"});
      if(q.moveToFirst()){org.json.JSONObject j=new org.json.JSONObject(q.getString(0));gluid=j.getString("data");}
      q.close();db.close();status.setText("GLUID извлечён из gameloft_sharing");
    }
    if(r==CREATE_OUT){try(OutputStream o=getContentResolver().openOutputStream(d.getData())){o.write(pendingOutput);}status.setText("Готово. Файл сохранения записан.");}
  }catch(Exception e){status.setText("Ошибка: "+e.getMessage());}}
  byte[] pendingOutput;
  void edit(){try{
    if(saveBytes==null||gluid==null)throw new Exception("Сначала выбери файл сохранения и gameloft_sharing.");
    long b=Long.parseLong(bits.getText().toString()),g=Long.parseLong(gems.getText().toString());
    byte[] xml=decodeSave(saveBytes,gluid.getBytes("UTF-8"));
    DocumentBuilderFactory f=DocumentBuilderFactory.newInstance();f.setFeature("http://apache.org/xml/features/disallow-doctype-decl",true);
    Document doc=f.newDocumentBuilder().parse(new ByteArrayInputStream(xml));
    Element pd=(Element)doc.getElementsByTagName("PlayerData").item(0);if(pd==null)throw new Exception("В XML нет PlayerData — формат сохранения отличается.");
    pd.setAttribute("Coins",Long.toString(b));pd.setAttribute("Hearts",Long.toString(g));
    Transformer t=TransformerFactory.newInstance().newTransformer();t.setOutputProperty(OutputKeys.ENCODING,"UTF-8");t.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION,"no");
    ByteArrayOutputStream x=new ByteArrayOutputStream();t.transform(new DOMSource(doc),new StreamResult(x));
    pendingOutput=encodeSave(x.toByteArray(),gluid.getBytes("UTF-8"));
    Intent i=new Intent(Intent.ACTION_CREATE_DOCUMENT);i.setType("application/octet-stream");i.putExtra(Intent.EXTRA_TITLE,"mlp_save_prime_modified.dat");startActivityForResult(i,CREATE_OUT);
  }catch(Exception e){status.setText("Не удалось изменить: "+e.getMessage());}}
  static int u32(int x){return x;}
  static int[] longs(byte[] a){int n=(a.length+3)/4;int[] v=new int[n];for(int i=0;i<a.length;i++)v[i/4]|=(a[i]&255)<<((i%4)*8);return v;}
  static byte[] bytes(int[] v,int len){byte[] a=new byte[len];for(int i=0;i<len;i++)a[i]=(byte)(v[i/4]>>>((i%4)*8));return a;}
  static int mx(int sum,int y,int z,int p,int e,int[] k){return (((z>>>5)^(y<<2))+((y>>>3)^(z<<4)))^((sum^y)+(k[(p&3)^e]^z));}
  static int[] btea(int[] v,boolean decrypt){int n=v.length;if(n<2)return v;int[] a=v.clone(),k=longs(new byte[16]);return a;}
  static byte[] xxtea(byte[] data,byte[] key,boolean decrypt){
    byte[] kk=new byte[16];System.arraycopy(key,0,kk,0,Math.min(key.length,16));int[] k=longs(kk),v=longs(data);int n=v.length;if(n<2)return data;
    int rounds=6+52/n,sum=0,y,z,e,p;
    if(!decrypt){z=v[n-1];for(int q=0;q<rounds;q++){sum+=0x9e3779b9;e=(sum>>>2)&3;for(p=0;p<n;p++){y=v[(p+1)%n];z=v[p]+=mx(sum,y,z,p,e,k);}}}
    else{sum=rounds*0x9e3779b9;y=v[0];while(sum!=0){e=(sum>>>2)&3;for(p=n-1;p>=0;p--){z=v[(p+n-1)%n];y=v[p]-=mx(sum,y,z,p,e,k);}sum-=0x9e3779b9;}}
    return bytes(v,v.length*4);
  }
  static byte[] cryptBuffer(byte[] raw,byte[] key,boolean dec)throws Exception{
    byte[] plain=xxtea(raw,key,dec);
    if(dec){Inflater z=new Inflater();z.setInput(plain);ByteArrayOutputStream o=new ByteArrayOutputStream();byte[] b=new byte[8192];while(!z.finished()){int n=z.inflate(b);if(n==0&&z.needsInput())break;o.write(b,0,n);}z.end();return o.toByteArray();}
    Deflater z=new Deflater();z.setInput(raw);z.finish();ByteArrayOutputStream o=new ByteArrayOutputStream();byte[] b=new byte[8192];while(!z.finished()){int n=z.deflate(b);o.write(b,0,n);}z.end();byte[] comp=o.toByteArray();CRC32 crc=new CRC32();crc.update(raw);ByteBuffer bb=ByteBuffer.allocate(comp.length+4).order(ByteOrder.LITTLE_ENDIAN);bb.put(comp).putInt((int)crc.getValue());return xxtea(bb.array(),key,false);
  }
  static byte[] decodeSave(byte[] src,byte[] key)throws Exception{
    ByteBuffer in=ByteBuffer.wrap(src).order(ByteOrder.LITTLE_ENDIAN);ByteArrayOutputStream out=new ByteArrayOutputStream();int sections=in.getInt(src.length-4);if(sections!=2)throw new Exception("Неизвестный формат: число секций не равно 2.");
    for(int s=0;s<2;s++){int usize=in.getInt(),crcOff=in.getInt(),size=in.getInt();byte[] raw=new byte[size];in.get(raw);byte[] p=xxtea(raw,key,true);if(s==0){out.write(p,0,Math.min(p.length,4));}else{Inflater inf=new Inflater();inf.setInput(p,0,crcOff-4);byte[] b=new byte[usize];int n=inf.inflate(b);inf.end();if(n!=usize)throw new Exception("Ошибка распаковки/ключ GLUID неверен.");CRC32 crc=new CRC32();crc.update(b);int stored=ByteBuffer.wrap(p,crcOff-4,4).order(ByteOrder.LITTLE_ENDIAN).getInt();if((int)crc.getValue()!=stored)throw new Exception("CRC не совпадает: сохранение повреждено или GLUID неверен.");return b;}}
    throw new Exception("Пустое сохранение.");
  }
  static byte[] encodeSave(byte[] xml,byte[] key)throws Exception{
    ByteArrayOutputStream out=new ByteArrayOutputStream();writeSection(out,ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(10).array(),key);writeSection(out,xml,key);out.write(new byte[]{2,0,0,0});return out.toByteArray();
  }
  static void writeSection(ByteArrayOutputStream out,byte[] raw,byte[] key)throws Exception{
    Deflater z=new Deflater();z.setInput(raw);z.finish();ByteArrayOutputStream c=new ByteArrayOutputStream();byte[] b=new byte[8192];while(!z.finished()){int n=z.deflate(b);c.write(b,0,n);}z.end();byte[] comp=c.toByteArray();CRC32 crc=new CRC32();crc.update(raw);ByteBuffer p=ByteBuffer.allocate(comp.length+4).order(ByteOrder.LITTLE_ENDIAN).put(comp).putInt((int)crc.getValue());byte[] enc=xxtea(p.array(),key,false);ByteBuffer h=ByteBuffer.allocate(12).order(ByteOrder.LITTLE_ENDIAN).putInt(raw.length).putInt(comp.length+4).putInt(enc.length);out.write(h.array());out.write(enc);
  }
}