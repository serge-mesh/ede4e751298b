import * as React from "react";
import {
  columnFilteringFeature,
  createFilteredRowModel,
  createSortedRowModel,
  filterFn_includesString,
  flexRender,
  globalFilteringFeature,
  rowSortingFeature,
  sortFn_alphanumeric,
  sortFn_datetime,
  sortFn_text,
  tableFeatures,
  useTable,
  type ColumnDef,
  type Row,
  type RowData,
  type SortingState,
} from "@tanstack/react-table";
import { ArrowDownIcon, ArrowUpIcon, ChevronsUpDownIcon, SearchIcon } from "lucide-react";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";

/**
 * The table features every DataTable registers: sorting and the global filter. The sort functions
 * are the ones `sortFn: "auto"` picks from, as TanStack Table v8 did by default.
 */
const dataTableFeatures = tableFeatures({
  rowSortingFeature,
  columnFilteringFeature,
  globalFilteringFeature,
  sortedRowModel: createSortedRowModel(),
  filteredRowModel: createFilteredRowModel(),
  sortFns: { alphanumeric: sortFn_alphanumeric, text: sortFn_text, datetime: sortFn_datetime },
  filterFns: { includesString: filterFn_includesString },
});

type DataTableFeatures = typeof dataTableFeatures;

/** A column of a DataTable over rows of type T. */
export type DataTableColumn<T extends RowData> = ColumnDef<DataTableFeatures, T, unknown>;

/**
 * A sortable, filterable table (TanStack Table). Cells render values as React text; columns
 * that show outside text use SafeText.
 */
export function DataTable<T extends RowData>({
  data,
  columns,
  searchable,
  searchPlaceholder = "Filter…",
  initialSort,
  empty,
  onRowClick,
  rowClassName,
  getRowId,
  toolbar,
  dense,
  label,
}: {
  data: T[];
  columns: DataTableColumn<T>[];
  searchable?: boolean;
  searchPlaceholder?: string;
  initialSort?: SortingState;
  empty?: React.ReactNode;
  onRowClick?: (row: T) => void;
  rowClassName?: (row: Row<DataTableFeatures, T>) => string | undefined;
  getRowId?: (row: T, index: number) => string;
  toolbar?: React.ReactNode;
  dense?: boolean;
  label?: string;
}) {
  const [sorting, setSorting] = React.useState<SortingState>(initialSort ?? []);
  const [filter, setFilter] = React.useState("");
  const table = useTable({
    features: dataTableFeatures,
    data,
    columns,
    state: { sorting, globalFilter: filter },
    onSortingChange: setSorting,
    onGlobalFilterChange: setFilter,
    getRowId,
    globalFilterFn: "includesString",
  });
  const rows = table.getRowModel().rows;
  return (
    <div className="space-y-3">
      {(searchable || toolbar) && (
        <div className="flex flex-wrap items-center gap-2">
          {searchable && (
            <div className="relative w-full max-w-xs">
              <SearchIcon className="pointer-events-none absolute top-2.5 left-2.5 size-4 text-muted-foreground" aria-hidden />
              <Input
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
                placeholder={searchPlaceholder}
                className="h-9 pl-8"
                aria-label={searchPlaceholder}
              />
            </div>
          )}
          {toolbar}
        </div>
      )}
      <div className="rounded-md border">
        <Table aria-label={label}>
          <TableHeader>
            {table.getHeaderGroups().map((hg) => (
              <TableRow key={hg.id} className="hover:bg-transparent">
                {hg.headers.map((h) => {
                  const sortable = h.column.getCanSort() && h.column.columnDef.enableSorting !== false;
                  const dir = h.column.getIsSorted();
                  return (
                    <TableHead key={h.id} aria-sort={dir === "asc" ? "ascending" : dir === "desc" ? "descending" : undefined}>
                      {h.isPlaceholder ? null : sortable ? (
                        <button
                          type="button"
                          className="inline-flex items-center gap-1 hover:text-foreground"
                          onClick={h.column.getToggleSortingHandler()}
                        >
                          {flexRender(h.column.columnDef.header, h.getContext())}
                          {dir === "asc" ? (
                            <ArrowUpIcon className="size-3" />
                          ) : dir === "desc" ? (
                            <ArrowDownIcon className="size-3" />
                          ) : (
                            <ChevronsUpDownIcon className="size-3 opacity-40" />
                          )}
                        </button>
                      ) : (
                        flexRender(h.column.columnDef.header, h.getContext())
                      )}
                    </TableHead>
                  );
                })}
              </TableRow>
            ))}
          </TableHeader>
          <TableBody>
            {rows.length === 0 ? (
              <TableRow className="hover:bg-transparent">
                <TableCell colSpan={columns.length} className="h-20 text-center text-sm text-muted-foreground">
                  {filter ? "Nothing matches the filter." : (empty ?? "Nothing here yet.")}
                </TableCell>
              </TableRow>
            ) : (
              rows.map((row) => (
                <TableRow
                  key={row.id}
                  className={cn(onRowClick && "cursor-pointer", rowClassName?.(row))}
                  onClick={onRowClick ? () => onRowClick(row.original) : undefined}
                  onKeyDown={
                    onRowClick
                      ? (e) => {
                          if (e.key === "Enter" && e.target === e.currentTarget) onRowClick(row.original);
                        }
                      : undefined
                  }
                  tabIndex={onRowClick ? 0 : undefined}
                >
                  {row.getAllCells().map((cell) => (
                    <TableCell key={cell.id} className={cn(dense && "py-1")}>
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </TableCell>
                  ))}
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
