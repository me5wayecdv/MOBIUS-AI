package com.mobius.ownedlab;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.net.Uri;

/** Owned synthetic fixture only. Intentionally exports one in-memory lab row. */
public class NotesProvider extends ContentProvider {
    private SQLiteDatabase database;

    @Override public boolean onCreate() {
        database = SQLiteDatabase.create(null);
        database.execSQL("CREATE TABLE notes (_id INTEGER PRIMARY KEY, body TEXT NOT NULL)");
        database.execSQL("INSERT INTO notes VALUES (1, 'MOBIUS_SYNTHETIC_LAB_ROW')");
        return true;
    }

    @Override public Cursor query(Uri uri, String[] projection, String selection,
                                  String[] selectionArgs, String sortOrder) {
        String authority = getClass() == PrivateProvider.class
                ? "com.mobius.ownedlab.private" : "com.mobius.ownedlab.notes";
        if (!authority.equals(uri.getAuthority()) || !"/note".equals(uri.getPath())
                || uri.getQuery() != null || uri.getFragment() != null) {
            throw new IllegalArgumentException("Only the fixed lab note route is supported");
        }
        // Caller selection reaches a SQLite sink for static may-flow analysis.
        // No writable SQL API is exposed; the approved read probe supplies no selection.
        return database.query("notes", new String[]{"_id", "body"}, selection,
                selectionArgs, null, null, null, "1");
    }

    @Override public String getType(Uri uri) { return "vnd.android.cursor.item/vnd.mobius.note"; }
    @Override public Uri insert(Uri uri, ContentValues values) { throw new UnsupportedOperationException("read-only"); }
    @Override public int update(Uri uri, ContentValues values, String selection, String[] args) { throw new UnsupportedOperationException("read-only"); }
    @Override public int delete(Uri uri, String selection, String[] args) { throw new UnsupportedOperationException("read-only"); }
    @Override public void shutdown() {
        if (database != null) { database.close(); }
        super.shutdown();
    }
}
