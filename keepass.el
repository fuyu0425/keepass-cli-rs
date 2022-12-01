(require 's)
(require 'cl)
(require 'dash)
(require 'hydra)

(defgroup keepass nil
  "Keepass"
  :group 'tools)

(defcustom keepass-binary "keepass-cli"
  "path of keepass cli binary"
  :type 'string
  :group 'keepass
  )

(defcustom keepass-database nil
  "path of keepass database"
  :type 'string
  :group 'keepass)

(defface keepass-title-face
  '((t :inherit font-lock-type-face :weight bold))
  "Face for title."
  :group 'keepass-faces)

(defcustom keepass-icon-width 16
  "icon width"
  :type 'number
  :group 'keepass)

(defcustom keepass-icon-height 16
  "icon height"
  :type 'number
  :group 'keepass)

(cl-defstruct keepass-entry "Keepass Entry without password" id title username url note has-otp icon)

(defvar keepass~all-entries nil "All entries (served as a cache)")

(defvar keepass~entry-map (make-hash-table) "Hash map from id to entry")

(defvar keepass-binary-path nil "keepass binary path")
;; process related; thanks to mu4e code for async process handling

;; dealing with the length cookie that precedes expressions
;; (defconst keepass~cookie-pre "\376")
;; (defconst keepass~cookie-post "\377")
(defconst keepass~cookie-pre "\303\276")
(defconst keepass~cookie-post "\303\277")

(defconst keepass~cookie-matcher-rx
  (concat keepass~cookie-pre "\\([[:xdigit:]]+\\)" keepass~cookie-post))

(defvar keepass-debug nil
  "When set to non-nil, log debug information to the *keepass-log* buffer.")

(defconst keepass~log-max-size 1000000
  "Max number of characters to keep around in the log buffer.")
(defconst keepass~log-buffer-name "*keepass-log*"
  "*internal* Name of the logging buffer.")

(defvar keepass-main-buffer-name "*keepass-main*"
  "Name of the keepass main view buffer. The default name starts
with SPC and therefore is not visible in buffer list.")

(defconst keepass~proc-name " *keepass-proc*"
  "Name of the server process, buffer.")

(defvar keepass~proc-process nil
  "The keepass-cli process.")

(defconst keepass~loading-message "Loading...")

(defun keepass-toggle-debug ()
  (interactive)
  (setq keepass-debug (not keepass-debug)))

(defsubst keepass~proc-eat-sexp-from-buf ()
  "'Eat' the next s-expression from `keepass~proc-buf'.
Note: this is a string, not an emacs-buffer. `keepass~proc-buf gets
its contents from the keepass-servers in the following form:
   <`keepass~cookie-pre'><length-in-hex><`keepass~cookie-post'>
Function returns this sexp, or nil if there was none.
`keepass~proc-buf' is updated as well, with all processed sexp data
removed."
  (ignore-errors ;; the server may die in the middle...
    ;; keepass~cookie-matcher-rx:
    ;;  (concat keepass~cookie-pre "\\([[:xdigit:]]+\\)]" keepass~cookie-post)
    (let ((b (string-match keepass~cookie-matcher-rx keepass~proc-buf))
          (sexp-len) (objcons))
      (when b
        (setq sexp-len (string-to-number (match-string 1 keepass~proc-buf) 16))
        ;; does keepass~proc-buf contain the full sexp?
        (when (>= (length keepass~proc-buf) (+ sexp-len (match-end 0)))
          ;; clear-up start
          (setq keepass~proc-buf (substring keepass~proc-buf (match-end 0)))
          ;; note: we read the input in binary mode -- here, we take the part
          ;; that is the sexp, and convert that to utf-8, before we interpret
          ;; it.
          (setq objcons (read-from-string
                         (decode-coding-string
                          (substring keepass~proc-buf 0 sexp-len)
                          'utf-8 t)))
          (when objcons
            (setq keepass~proc-buf (substring keepass~proc-buf sexp-len))
            (car objcons)))))))


(defun keepass~proc-filter (_proc str)
  (keepass-log 'misc "* Received %d byte(s)" (length str))
  (setq keepass~proc-buf (concat keepass~proc-buf str)) ;; update our buffer
  (keepass-log 'misc "%s" keepass~proc-buf)
  (let ((sexp (keepass~proc-eat-sexp-from-buf)))
    (with-local-quit
      (while sexp
        (keepass-log 'from-server "%S" sexp)
        (cond

         ((plist-get sexp :list)
          (keepass~list-callback sexp))

         ((plist-get sexp :get)
          (keepass~get-callback sexp))

         (t (message "Unexpected data from server [%S]" sexp)))

        (setq sexp (keepass~proc-eat-sexp-from-buf))))))

(defun keepass~get-log-buffer ()
  "Fetch (and maybe create) the log buffer."
  (unless (get-buffer keepass~log-buffer-name)
    (with-current-buffer (get-buffer-create keepass~log-buffer-name)
      (view-mode)

      (when (fboundp 'so-long-mode)
        (unless (eq major-mode 'so-long-mode)
          (eval '(so-long-mode))))

      (setq buffer-undo-list t)))
  keepass~log-buffer-name)

(defun keepass-log (type frm &rest args)
  "Write a message of TYPE with format-string FRM and ARGS in
*keepass-log* buffer, if the variable keepass-debug is non-nil. Type is
either 'to-server, 'from-server or 'misc. This function is meant for debugging."
  (when keepass-debug
    (with-current-buffer (keepass~get-log-buffer)
      (let* ((inhibit-read-only t)
             (tstamp (propertize (format-time-string "%Y-%m-%d %T.%3N"
                                                     (current-time))
                                 'face 'font-lock-string-face))
             (msg-face
              (cl-case type
                (from-server 'font-lock-type-face)
                (to-server   'font-lock-function-name-face)
                (misc        'font-lock-variable-name-face)
                (error       'font-lock-warning-face)
                (otherwise   (keepass-error "Unsupported log type"))))
             (msg (propertize (apply 'format frm args) 'face msg-face)))
        (save-excursion
          (goto-char (point-max))
          (insert tstamp
                  (cl-case type
                    (from-server " <- ")
                    (to-server   " -> ")
                    (error       " !! ")
                    (otherwise   " "))
                  msg "\n")

          ;; if `keepass-log-max-lines is specified and exceeded, clearest the oldest
          ;; lines
          (when (> (buffer-size) keepass~log-max-size)
            (goto-char (- (buffer-size) keepass~log-max-size))
            (beginning-of-line)
            (delete-region (point-min) (point))))))))

(defun keepass-format (frm &rest args)
  "Create [keepass]-prefixed string based on format FRM and ARGS."
  (concat
   "[" (propertize "keepass" 'face 'keepass-title-face) "] "
   (apply 'format frm
          (mapcar (lambda (x)
                    (if (stringp x)
                        (decode-coding-string x 'utf-8)
                      x))
                  args))))

(defun keepass-error (frm &rest args)
  "Create [keepass]-prefixed error based on format FRM and ARGS.
Does a local-exit and does not return, and raises a
debuggable (backtrace) error."
  (keepass-log 'error (apply 'keepass-format frm args))
  (error "%s" (apply 'keepass-format frm args)))

(defun keepass~proc-sentinel (proc _msg)
  "Function called when the server process PROC terminates with MSG."
  (let ((status (process-status proc)) (code (process-exit-status proc)))
    (setq keepass~proc-process nil)
    (setq keepass~proc-buf "") ;; clear any half-received sexps
    (cond
     ((eq status 'signal)
      (cond
       ((or(eq code 9) (eq code 2)) (message nil))
       ;;(message "the keepass server process has been stopped"))
       (t (error (format "keepass server process received signal %d" code)))))
     ((eq status 'exit)
      (cond
       ((eq code 0)
        (message nil)) ;; don't do anything
       ((eq code 19)
        (error "Database is locked by another process"))
       (t (error "Keepass server process ended with exit code %d" code))))
     (t
      (error "Something bad happened to the keepass server process")))))

(defun keepass~proc-start ()
  "Start the keepass server process."
  (interactive)

  (unless keepass-binary-path
    (setq keepass-binary-path (executable-find keepass-binary)))

  ;; sanity-check 1
  (unless (and keepass-binary-path (file-executable-p keepass-binary-path))
    (keepass-error
     "Cannot find keepass from `keepass-binary' in PATH,
      please set `keepass-binary-path' diretly to the keepass executable path"))

  (unless (and keepass-database (file-exists-p keepass-database))
    (keepass-error
     "Cannot find keepass database, please set `keepass-database' to the keepass database path"))

  (let* ((process-connection-type nil) ;; use a pipe
         (args nil)
         (args (cons "server" args))
         (args (cons "-e" args))
         (args (cons keepass-database args))
         (args (cons "-d" args))
         (db-pw (password-read
                 (format "Password for %s: " keepass-database)
                 keepass-database))
         (args (cons "--icon" args)))
    (keepass-log 'misc "%S" args)
    (setq keepass~all-entries nil)
    (clrhash keepass~entry-map)
    (setq keepass-current-selected-id nil
          keepass-current-selected nil)
    (setq keepass~proc-buf "")
    (setq keepass~proc-process (apply 'start-process
                                      keepass~proc-name keepass~proc-name
                                      keepass-binary-path args))
    ;; register a function for (:info ...) sexps
    (unless keepass~proc-process
      (keepass-error "Failed to start the keepass backend"))
    ;; NOTE: authentication
    (process-send-string keepass~proc-process db-pw)
    (process-send-string keepass~proc-process "\n")
    (password-cache-add keepass-database db-pw)
    ;;
    (set-process-query-on-exit-flag keepass~proc-process nil)
    (set-process-coding-system keepass~proc-process 'binary 'utf-8-unix)
    (set-process-filter keepass~proc-process 'keepass~proc-filter)
    (set-process-sentinel keepass~proc-process 'keepass~proc-sentinel)))

(defun keepass~proc-kill ()
  "Kill the keepass server process."
  (interactive)
  (let* ((buf (get-buffer keepass~proc-name))
         (proc (and (buffer-live-p buf) (get-buffer-process buf))))
    (when proc
      (let ((delete-exited-processes t))
        (keepass~call "quit"))
      ;; try sending SIGINT (C-c) to process, so it can exit gracefully
      (ignore-errors
        (signal-process proc 'SIGINT))))
  (setq
   keepass~all-entries nil
   keepass~proc-process nil
   keepass~proc-buf nil))

(defun keepass~proc-running-p  ()
  "Whether the keepass-cli process is running."
  (and keepass~proc-process
       (memq (process-status keepass~proc-process)
             '(run open listen connect stop))
       t))

(defun keepass~call (form)
  "Call 'keepass' with some command."
  (unless (keepass~proc-running-p) (keepass~proc-start))
  (let* ((print-length nil) (print-level nil)
         (cmd (format "%s" form)))
    (keepass-log 'to-server "%s" cmd)
    (process-send-string keepass~proc-process (concat cmd "\n"))))

(defun keepass~list-callback (sexp)
  (let* ((data (plist-get sexp :data))
         (field (plist-get sexp :field))
         (show (plist-get sexp :show))
         (copy (plist-get sexp :copy))
         (msg (plist-get sexp :msg))
         (server-msg (plist-get sexp :server-msg)))
    (dolist (entry data)
      (let* ((fields entry)
             (fields-with-key (-interleave field fields))
             (m (apply 'make-keepass-entry fields-with-key)))
        (push m keepass~all-entries)
        (puthash (keepass-entry-id m) m keepass~entry-map)))
    (when show
      (when (or msg server-msg)
        (message "%s %s" (or msg "") (or server-msg ""))))))

(defun keepass~get-callback (sexp)
  (let* ((data (plist-get sexp :data))
         (field (plist-get sexp :field))
         (show (plist-get sexp :show))
         (copy (plist-get sexp :copy))
         (msg (plist-get sexp :msg))
         (server-msg (plist-get sexp :server-msg))
         (val (caar data)))
    (when show
      (when (or msg server-msg)
        (message "%s %s" (or msg "") (or server-msg ""))))
    (when copy
      (kill-new val))))


(defun keepass--reload ()
  (interactive)
  (keepass~call "reload"))

(defun keepass-refresh ()
  "Refresh the entries."
  (interactive)
  (keepass--reload)
  (setq keepass~all-entries nil)
  (clrhash keepass~entry-map)
  (keepass-list))

(defun keepass-list ()
  "List all entries and cache them in `keepass~all-entries'"
  (interactive)
  (unless keepass~all-entries (keepass~call "ls -f id title username url note has-otp icon")))


(defun keepass--get (id field &optional show copy)
  ;; (unless keepass~all-entries (keepass-list))
  (let* ((cmd (format "get %d -f %s" id field))
         (cmd  (if show (format "%s -s" cmd) cmd))
         (cmd  (if copy (format "%s -c" cmd) cmd))
         (msg (format "%s is copied." field))
         (cmd  (if show (format "%s -m \"%s\"" cmd msg) cmd)))
    (keepass~call cmd)))


(defvar keepass-current-selected-id nil)
(defvar keepass-current-selected nil)

(defun keepass-get (field &optional show copy)
  (interactive)
  (keepass--get keepass-current-selected-id field show copy))

(defun keepass--format-icon (icon-path)
  (if icon-path (propertize "<"
                        'display
                           `(image
                            :type imagemagick
                            :file ,icon-path
                            ;; :scale 1
                            :width ,keepass-icon-width
                            :height ,keepass-icon-height
                            :format nil
                            :transform-smoothing t
                            ;; :relief 1
                            :ascent center
                            )
                           ;; 'rear-nonsticky
                           ;; '(display)
                           ;; 'front-sticky
                           ;; '(read-only)
                           ;; 'fontified
                           ;; t
                           )
    " "))

(defun keepass--format-entry (entry)
  (let* (
         (id (keepass-entry-id entry))
         (title (keepass-entry-title entry))
         (username (keepass-entry-username entry))
         (url (keepass-entry-url entry))
         (note (keepass-entry-note entry))
         (has-otp (keepass-entry-has-otp entry))
         (icon (keepass-entry-icon entry))
         (item-str (format "Title: %s\nUsername: %s\nURL: %s%2s\nNote: %s\nHas-OTP: %s"
                           (propertize title 'face 'font-lock-type-face)
                           (propertize username 'face 'font-lock-function-name-face)
                           (propertize url 'face 'font-lock-variable-name-face)
                           (keepass--format-icon icon)
                           note
                           (propertize (if has-otp "Yes" "No")  'face 'font-lock-warning-face)
                           )))
    item-str))

(cl-defun keepass-select (&optional init-value)
  "Select entry based on completing-read."
  (interactive)
  (unless keepass~all-entries
    (message "Loading entries; try later")
    (cl-return-from keepass-select))
  (let* ((objects nil))
    (dolist (entry keepass~all-entries)
      (let* (
             (id (keepass-entry-id entry))
             (title (keepass-entry-title entry))
             (title (truncate-string-to-width title 20 0 ?\s t))
             (username (keepass-entry-username entry))
             (username (truncate-string-to-width username 20 0 ?\s t))
             (url (keepass-entry-url entry))
             (url (truncate-string-to-width url 20 0 ?\s t))
             (note (keepass-entry-note entry))
             (icon (keepass-entry-icon entry))
             (item-str (format "%s %-20s\t%-20s\t%-20s\t%s"
                               (keepass--format-icon icon)
                               (propertize title 'face 'font-lock-type-face)
                               ;; title
                               (propertize username 'face 'font-lock-function-name-face)
                               ;; username
                               ;; url
                               (propertize url 'face 'font-lock-variable-name-face)
                               note)))
        (put-text-property 0 (length item-str) 'id id item-str)
        (push item-str objects)))
    (let* ((chosen-id (get-text-property 0 'id
                                         (completing-read "Select: " objects nil t init-value))))
      (setq keepass-current-selected-id chosen-id)
      (setq keepass-current-selected (gethash chosen-id keepass~entry-map))
      (keepass-update-hydra-hint)
      (keepass~main-redraw-buffer))))

(cl-defun keepass-select-by-title (selected-title)
  "Select entry based on its title.
If there are two entries sharing the same title, the first one is returned."
  (interactive)
  (unless keepass~all-entries
    (message "Loading entries; try later")
    (cl-return-from keepass-select-by-title))
  (let* ((objects nil))
    (dolist (entry keepass~all-entries)
      (let* (
             (id (keepass-entry-id entry))
             (title (keepass-entry-title entry))
             (username (keepass-entry-username entry))
             (url (keepass-entry-url entry))
             (note (keepass-entry-note entry)))
        (when (string-equal selected-title title)
          (setq keepass-current-selected-id id)
          (setq keepass-current-selected (gethash id keepass~entry-map))
          (keepass-update-hydra-hint)
          (keepass~main-redraw-buffer)
          (cl-return))))))

;; main buffer
(defun keepass~main-view ()
  "Create the keepass main-view, and switch to it.

When REFRESH is non nil refresh infos from server."
  (let ((buf (get-buffer-create keepass-main-buffer-name)))
    ;; `keepass~main-view' is called from `keepass~start', so don't call it
    ;; a second time here i.e. do not refresh unless specified
    ;; explicitly with REFRESH arg.
    (switch-to-buffer buf)
    (with-current-buffer buf
      (keepass~main-redraw-buffer))
    (goto-char (point-min))))

(defun keepass~main-redraw-buffer ()
  (when (bufferp keepass-main-buffer-name)
    (with-current-buffer keepass-main-buffer-name
      (let ((inhibit-read-only t)
            (pos (point)))
        (erase-buffer)
        (if keepass-current-selected
            (insert (keepass--format-entry keepass-current-selected))
          (insert (format "No entry is selected. Please press \".\" or \"?\" to start.")))
        (keepass-main-mode)
        (goto-char pos)))))

(defhydra keepass-hydra (:hint nil)
  ""
  ("s" keepass-select "select entry")
  ("f" keepass-hydra-favorite/body "favorites" :exit t)
  ("r" keepass-refresh "refresh")
  ("u" (lambda () (interactive) (keepass-get "username" t t)) "copy username")
  ("p" (lambda () (interactive) (keepass-get "password" t t)) "copy password")
  ("o" (lambda () (interactive) (keepass-get "otp" t t)) "copy otp")
  ("q" (lambda () (interactive)
         (when (string-equal (buffer-name) keepass-main-buffer-name)
           (quit-window)))
   "quit" :color blue))

(setq keepass-hydra-original-hint keepass-hydra/hint)

(defun keepass-update-hydra-hint ()
  (interactive)
  (setq keepass-hydra/hint
        (concat
         (format "%s\n" (if keepass-current-selected (keepass--format-entry keepass-current-selected) "Selected: None"))
         keepass-hydra-original-hint)))

;; alternative method https://github.com/abo-abo/hydra/wiki/Conditional-Hydra
;; but it will append ":"
;; (setq keepass-hydra/hint
;;       '(eval (hydra--format nil '(nil nil :hint nil)
;;                             (format "%s\n"
;;                                     (if keepass-current-selected
;;                                         (keepass--format-entry keepass-current-selected)
;;                                       "Selected: None"))
;;                                   keepass-hydra/heads)))



;;;###autoload
(defmacro keepass-make-hydra-favorite (&rest heads)
  "API looks like this
(keepass-make-hydra-favorite
 (\"g\" \"gatech\")  ;; key, title pair
 (\"f\" \"ffxiv\"))"
  (setq heads (copy-tree heads))
  (let* ((pairs nil))
    (dolist (h heads)
      (let* ((key (car h))
             (title (cadr h)))
        (push `(,key
                (lambda () (interactive) (keepass-select-by-title ,title) (keepass-hydra/body))
                ,title
                :exit t)
              pairs)))
    `(defhydra keepass-hydra-favorite (:hint nil) "Favorite Entries"
       ,@pairs
       ("q" keepass-hydra/body "quit" :exit t))))

;; example
;; (keepass-make-hydra-favorite
;;  ("t" "test")
;;  ("o" "totp seed"))

(defvar keepass-main-mode-map
  (let ((map (make-sparse-keymap)))
    (define-key map "." 'keepass-hydra/body)
    (define-key map "?" 'keepass-hydra/body)
    map)
  "Keymap for the *keepass-main* buffer.")

(define-derived-mode keepass-main-mode special-mode "keepass:main"
  "Major mode for the keepass main screen.
\\{keepass-main-mode-map}."
  (setq truncate-lines t
        overwrite-mode 'overwrite-mode-binary)
  (set (make-local-variable 'revert-buffer-function) #'keepass~main-redraw-buffer))

;;;###autoload
(defun keepass (&optional inplace)
  "Lanuch keepass. Switch to the keepass special buffer unless
  BACKGROUND (prefix-argument) is non-nil"
  (interactive "P")
  (unless (keepass~proc-running-p)
    (keepass~proc-start))
  (unless keepass~all-entries (keepass-list))
  (keepass-update-hydra-hint)
  (unless inplace (keepass~main-view))
  (keepass-hydra/body))

;;;###autoload
(defun keepass-inplace ()
  "Lanuch keepass inplace."
  (interactive)
  (keepass t))

;; TODO can we show svg icon for domain?

;; TODO clear keyring
;; 1. create a timer
;; 2. queue (time . password), and pop expired item can clear kill ring
;; 3. destory the timer when queue is empty
;; (time-convert (current-time) 'integer)

(provide 'keepass)
