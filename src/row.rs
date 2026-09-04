//! A decoded result row and typed access to its columns.

use crate::error::{Error, Result};
use crate::message::FieldDescription;
use crate::types::FromSql;
use std::sync::Arc;

/// One row of a result set. Columns are stored as their raw text-format bytes
/// (or `None` for SQL NULL) alongside a shared handle to the column metadata, so
/// a row can be read by index or by column name.
#[derive(Debug, Clone)]
pub struct Row {
    columns: Arc<Vec<FieldDescription>>,
    values: Vec<Option<Vec<u8>>>,
}

impl Row {
    pub(crate) fn new(columns: Arc<Vec<FieldDescription>>, values: Vec<Option<Vec<u8>>>) -> Self {
        Row { columns, values }
    }

    /// Number of columns.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// The column descriptions (name, type OID, format, ...).
    pub fn columns(&self) -> &[FieldDescription] {
        &self.columns
    }

    /// Decode column `idx` (a `usize` position or a `&str` name) into `T`.
    ///
    /// Returns an error if the column does not exist, if it is NULL and `T` is
    /// not an `Option`, or if the bytes do not decode into `T`.
    pub fn get<T: FromSql, I: RowIndex>(&self, idx: I) -> Result<T> {
        let i = idx.index(self)?;
        let oid = self.columns[i].type_oid;
        match &self.values[i] {
            None => T::from_sql_null(),
            Some(raw) => T::from_sql(oid, raw),
        }
    }

    /// The raw text-format bytes of a column, or `None` for NULL.
    pub fn get_bytes<I: RowIndex>(&self, idx: I) -> Result<Option<&[u8]>> {
        let i = idx.index(self)?;
        Ok(self.values[i].as_deref())
    }
}

/// Something that can name a column: a numeric position or a column name.
pub trait RowIndex {
    fn index(&self, row: &Row) -> Result<usize>;
}

impl RowIndex for usize {
    fn index(&self, row: &Row) -> Result<usize> {
        if *self < row.values.len() {
            Ok(*self)
        } else {
            Err(Error::ColumnNotFound(format!(
                "index {self} out of range for {} columns",
                row.values.len()
            )))
        }
    }
}

impl RowIndex for &str {
    fn index(&self, row: &Row) -> Result<usize> {
        row.columns
            .iter()
            .position(|c| c.name == *self)
            .ok_or_else(|| Error::ColumnNotFound((*self).to_string()))
    }
}
