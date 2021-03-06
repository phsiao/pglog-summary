
Introduction
------------

A simple python script that parses PostgreSQL log and produces a meaningful
summary.

Requirements
------------

Python 2.5+

Some details
------------

The log summarizer group messages into the following categories:

   - `Unknown`    representing log entries that this script does not recognize

   - `Fatal`      postgres FATAL event

   - `Error`      postgres ERROR event (typically followed by a CONTEXT and/or a STATEMENT)

   - `Warning`    postgres WARNING event

   - `Log`        misc. postgres LOG event

The script tried to group CONTEXT, STATEMENT, and DETAIL event with
their corresponding event.  This is done by remembering the last
event that is recorded to the same IP.

For the log event, the script also digest the following events:

   - checkpoint complete

   - automatic analyze of table

   - automatic vacuum of table

   - slow query
