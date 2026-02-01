-- Root table: one row per analyzed binary                                     
  CREATE TABLE IF NOT EXISTS binaries (                                                        
      id            INTEGER PRIMARY KEY AUTOINCREMENT,                           
      name          TEXT NOT NULL,                                               
      filepath      TEXT NOT NULL UNIQUE,                                        
      format        TEXT,                -- "MACHO" | "ELF" | "PE"               
      image_base    TEXT,                                                        
      entrypoint    TEXT,                                                        
      architecture  TEXT,                                                        
      bits          INTEGER,
      min_address   TEXT,                                                        
      max_address   TEXT,                                                        
      virtual_size  TEXT,                                                        
      original_size INTEGER,                                                     
      created_at    DATETIME DEFAULT CURRENT_TIMESTAMP                           
  );                                                                             
                                                                                 
  -- Security features per binary                                                
   CREATE TABLE IF NOT EXISTS security_features (                                               
      id            INTEGER PRIMARY KEY AUTOINCREMENT,                           
      binary_id     INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,  
      pie           BOOLEAN,                                                     
      nx            BOOLEAN,                                                     
      aslr          BOOLEAN,                                                     
      relro         TEXT,                -- "full" | "partial" | "none" | null   
      stack_canary  BOOLEAN,                                                     
      rwx_sections  TEXT,                -- JSON array of section names          
      pe_features   TEXT,                -- JSON blob for PE-specific            
      elf_features  TEXT,                -- JSON blob for ELF-specific           
      macho_features TEXT                -- JSON blob for Mach-O-specific        
  );                                                                             
                                                                                 
  -- Imports                                                                     
   CREATE TABLE IF NOT EXISTS imports (                                                         
      id            INTEGER PRIMARY KEY AUTOINCREMENT,                           
      binary_id     INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,  
      name          TEXT NOT NULL,                                               
      address       TEXT NOT NULL                                                
  );                                                                             
                                                                                 
  -- Exports                                                                     
  CREATE TABLE IF NOT EXISTS exports (                                                         
      id            INTEGER PRIMARY KEY AUTOINCREMENT,                           
      binary_id     INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,  
      name          TEXT NOT NULL,                                               
      address       TEXT NOT NULL                                                
  );                                                                             
                                                                                 
  -- Linked libraries                                                            
  CREATE TABLE IF NOT EXISTS libraries (                                                       
      id                    INTEGER PRIMARY KEY AUTOINCREMENT,                   
      binary_id             INTEGER NOT NULL REFERENCES binaries(id) ON DELETE   
  CASCADE,                                                                       
      name                  TEXT NOT NULL,                                       
      current_version       TEXT,                                                
      compatibility_version TEXT                                                 
  );                                                                             
                                                                                 
  -- Strings (one row per string)
  CREATE TABLE IF NOT EXISTS strings (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      binary_id     INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
      category      TEXT NOT NULL,       -- "ascii" | "utf16" | "stack" | "tight" | "decode"
      value         TEXT NOT NULL
  );                                                                             
                                                                                 
  -- Functions from Ghidra                                                       
  CREATE TABLE IF NOT EXISTS functions (                                                       
      id            INTEGER PRIMARY KEY AUTOINCREMENT,                           
      binary_id     INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,  
      name          TEXT NOT NULL,                                               
      address       TEXT NOT NULL,                                               
      size          INTEGER,                                                     
      decompiled    TEXT,                -- C pseudocode from Ghidra             
      UNIQUE(binary_id, address)                                                 
  );                                                                             
                                                                                 
  -- Call graph edges (function-to-function)                                     
  CREATE TABLE IF NOT EXISTS call_graph_nodes (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      binary_id     INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
      address       TEXT NOT NULL,
      name          TEXT NOT NULL,
      type          TEXT,                -- "thunk" | "external" | return type string
      UNIQUE(binary_id, address)
  );                                                                             
                                                                                 
  CREATE TABLE IF NOT EXISTS call_graph_edges (                                                
      id            INTEGER PRIMARY KEY AUTOINCREMENT,                           
      binary_id     INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,  
      src           TEXT NOT NULL,       -- source function address              
      dst           TEXT NOT NULL        -- destination function address         
  );                                                                             
                                                                                 
  -- CFG basic blocks (per function)                                             
  CREATE TABLE IF NOT EXISTS cfg_nodes (                                                       
      id            INTEGER PRIMARY KEY AUTOINCREMENT,                           
      binary_id     INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,  
      function_addr TEXT NOT NULL,       -- which function this block belongs to 
      block_id      TEXT NOT NULL,       -- hex address of block start           
      start_addr    TEXT NOT NULL,                                               
      end_addr      TEXT NOT NULL,                                               
      UNIQUE(binary_id, function_addr, block_id)                                 
  );                                                                             
                                                                                 
  CREATE TABLE IF NOT EXISTS cfg_edges (                                                       
      id            INTEGER PRIMARY KEY AUTOINCREMENT,                           
      binary_id     INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,  
      function_addr TEXT NOT NULL,                                               
      src           TEXT NOT NULL,                                               
      dst           TEXT NOT NULL,                                               
      type          TEXT                 -- "CONDITIONAL_JUMP", "UNCONDITIONAL_JUMP", etc.
  );                                                                             
                                                                                 
  -- User-created note nodes (from graphStore)                                   
  CREATE TABLE IF NOT EXISTS user_nodes (                                                      
      id            INTEGER PRIMARY KEY AUTOINCREMENT,                           
      binary_id     INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,  
      node_id       TEXT NOT NULL,       -- React Flow node ID                   
      position_x    REAL,                                                        
      position_y    REAL,                                                        
      data          TEXT,                -- JSON blob of node data               
      UNIQUE(binary_id, node_id)                                                 
  );                                                                             
                                                                                 
  -- User-created edges (from graphStore)                                        
  CREATE TABLE IF NOT EXISTS user_edges (                                                      
      id            INTEGER PRIMARY KEY AUTOINCREMENT,                           
      binary_id     INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,  
      edge_id       TEXT NOT NULL,       -- React Flow edge ID                   
      source        TEXT NOT NULL,                                               
      target        TEXT NOT NULL,                                               
      UNIQUE(binary_id, edge_id)                                                 
  );    