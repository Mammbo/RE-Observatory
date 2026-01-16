import { useState, useRef, useEffect } from "react";
import { Handle, Position } from "@xyflow/react";
import ReactMarkdown from "react-markdown";


// make the size changeable, add all of this into tailwind css, , and add customized scroll bar

const NoteNode = ({data}) => { 

  const [markdown, setMarkdown] = useState(
    data?.content ||
      `# Welcome to Notes

Type **Markdown** here and see it render instantly.

- Supports lists
- Bold and *italic*
- \`code blocks\`
- And more!`
  );
  const [isEditing, setIsEditing] = useState(false);
  const textareaRef = useRef(null);

  useEffect(() => {
    if (isEditing && textareaRef.current) {
      textareaRef.current.focus();
      textareaRef.current.selectionStart = textareaRef.current.value.length;
    }
  }, [isEditing]);

  return (
    <div
      style={{
        width: 300,
        height: 300,
        display: "flex",
        flexDirection: "column",
        background: "#1e1e2e",
        borderRadius: "8px",
        border: "2px solid #313244",
        boxShadow: "0 4px 12px rgba(0,0,0,0.3)",
        overflow: "hidden"
      }}
    >

      {/* Unified Content Area - both elements always in DOM for transitions */}
      <div className="relative flex-1 overflow-hidden">
        {/* Preview Layer */}
        <div
          onClick={() => setIsEditing(true)}
          className={`absolute inset-0 overflow-auto transition-all duration-300 ease-out cursor-pointer
            ${isEditing
              ? 'opacity-0 -translate-y-4 pointer-events-none'
              : 'opacity-100 translate-y-0'
            }`}
          style={{
            padding: "14px",
            fontSize: "13px",
            lineHeight: "1.6",
            color: "#cdd6f4",
            cursor: "text",
          }}
        >
            <ReactMarkdown
              components={{
                h1: ({ node, ...props }) => (
                  <h1
                    style={{
                      fontSize: "20px",
                      fontWeight: "700",
                      margin: "0 0 12px 0",
                      color: "#cba6f7",
                      paddingBottom: "8px",
                    }}
                    {...props}
                  />
                ),
                h2: ({ node, ...props }) => (
                  <h2
                    style={{
                      fontSize: "17px",
                      fontWeight: "600",
                      margin: "16px 0 8px 0",
                      color: "#89b4fa",
                    }}
                    {...props}
                  />
                ),
                h3: ({ node, ...props }) => (
                  <h3
                    style={{
                      fontSize: "15px",
                      fontWeight: "600",
                      margin: "12px 0 6px 0",
                      color: "#94e2d5",
                    }}
                    {...props}
                  />
                ),
                p: ({ node, ...props }) => (
                  <p style={{ margin: "8px 0", color: "#cdd6f4" }} {...props} />
                ),
                ul: ({ node, ...props }) => (
                  <ul
                    style={{
                      marginLeft: "20px",
                      margin: "8px 0 8px 20px",
                      listStyleType: "disc",
                    }}
                    {...props}
                  />
                ),
                ol: ({ node, ...props }) => (
                  <ol
                    style={{
                      marginLeft: "20px",
                      margin: "8px 0 8px 20px",
                      listStyleType: "decimal",
                    }}
                    {...props}
                  />
                ),
                li: ({ node, ...props }) => (
                  <li style={{ margin: "4px 0", color: "#bac2de" }} {...props} />
                ),
                code: ({ node, inline, ...props }) =>
                  inline ? (
                    <code
                      style={{
                        background: "#313244",
                        color: "#f38ba8",
                        padding: "2px 6px",
                        borderRadius: "4px",
                        fontSize: "12px",
                        fontFamily: "'JetBrains Mono', monospace",
                      }}
                      {...props}
                    />
                  ) : (
                    <code
                      style={{
                        display: "block",
                        background: "#11111b",
                        color: "#a6e3a1",
                        padding: "12px",
                        borderRadius: "6px",
                        fontSize: "12px",
                        fontFamily: "'JetBrains Mono', monospace",
                        overflow: "auto",
                        margin: "8px 0",
                      }}
                      {...props}
                    />
                  ),
                pre: ({ node, ...props }) => (
                  <pre
                    style={{
                      margin: "8px 0",
                      background: "#11111b",
                      borderRadius: "6px",
                      overflow: "auto",
                    }}
                    {...props}
                  />
                ),
                blockquote: ({ node, ...props }) => (
                  <blockquote
                    style={{
                      borderLeft: "4px solid #cba6f7",
                      paddingLeft: "14px",
                      marginLeft: "0",
                      color: "#a6adc8",
                      fontStyle: "italic",
                      margin: "12px 0",
                    }}
                    {...props}
                  />
                ),
                strong: ({ node, ...props }) => (
                  <strong style={{ color: "#fab387", fontWeight: "600" }} {...props} />
                ),
                em: ({ node, ...props }) => (
                  <em style={{ color: "#f9e2af" }} {...props} />
                ),
                a: ({ node, ...props }) => (
                  <a
                    style={{ color: "#89b4fa", textDecoration: "underline" }}
                    {...props}
                  />
                ),
                hr: ({ node, ...props }) => (
                  <hr
                    style={{
                      border: "none",
                      borderTop: "1px solid #313244",
                      margin: "16px 0",
                    }}
                    {...props}
                  />
                ),
              }}
            >
              {markdown}
            </ReactMarkdown>
        </div>

        {/* Editor Layer */}
        <textarea
          ref={textareaRef}
          value={markdown}
          onChange={(e) => setMarkdown(e.target.value)}
          onBlur={() => setIsEditing(false)}
          placeholder="Write Markdown here..."
          className={`absolute inset-0 transition-all duration-300 ease-out
            ${isEditing
              ? 'opacity-100 translate-y-0'
              : 'opacity-0 translate-y-4 pointer-events-none'
            }`}
          style={{
            padding: "14px",
            fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
            fontSize: "13px",
            border: "none",
            resize: "none",
            outline: "none",
            background: "#1e1e2e",
            color: "#cdd6f4",
            lineHeight: "1.6",
          }}
        />
      </div>

      {/* Handles for connections */}
      <Handle type="target" position={Position.Top} />
      <Handle type="source" position={Position.Bottom} />
    </div>
  );
}

export default NoteNode