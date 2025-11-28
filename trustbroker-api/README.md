# APIs

XTB APIs that can be implemented by others. These APIs are often still evolving, check the Javadoc of the respective classes
for details.

Rules to put classes into API:

- Contains only service interfaces and classes/interfaces for the parameters they require.
- Avoid dependencies to non-standard libraries if possible, unless the API is only relevant in connection with that library.
