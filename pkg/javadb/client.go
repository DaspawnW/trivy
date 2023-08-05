package javadb

import (
	"crypto/tls"
	"errors"
	"fmt"
	"golang.org/x/xerrors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"os"
	"path/filepath"
	"sort"

	"github.com/aquasecurity/go-dep-parser/pkg/java/jar"
	"github.com/aquasecurity/trivy-java-db/pkg/db"
	"github.com/aquasecurity/trivy-java-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/daspawnw/trivy-java-db-server/pkg/clientpb"
)

const (
	mediaType = "application/vnd.aquasec.trivy.javadb.layer.v1.tar+gzip"
)

var updater *Updater

type Updater struct {
	repo     string
	dbDir    string
	skip     bool
	quiet    bool
	insecure bool
}

func (u *Updater) Update() error {
	log.Logger.Info("The Java DB is not updated as this is a self compiled version that utilizes github.com/daspawnw/trivy-java-db-server as remote server to host the Java DB.")
	return nil
}

func Init(cacheDir string, javaDBRepository string, skip, quiet, insecure bool) {
	updater = &Updater{
		repo:     fmt.Sprintf("%s:%d", javaDBRepository, db.SchemaVersion),
		dbDir:    filepath.Join(cacheDir, "java-db"),
		skip:     skip,
		quiet:    quiet,
		insecure: insecure,
	}
}

func Update() error {
	log.Logger.Info("The Java DB is not updated as this is a self compiled version that utilizes github.com/daspawnw/trivy-java-db-server as remote server to host the Java DB.")
	return nil
}

type DB struct {
	client clientpb.JavaDBClient
}

func NewClient() (*DB, error) {
	addr := os.Getenv("JAVA_DB_SERVER_ADDR")
	if len(addr) == 0 {
		return nil, errors.New("No JAVA_DATABASE_ADDR environment variable provided")
	}

	config := &tls.Config{
		InsecureSkipVerify: false,
	}
	var opts []grpc.DialOption
	opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(config)))

	client, err := clientpb.NewJavaDBClient(addr, opts)
	if err != nil {
		return nil, err
	}
	return &DB{client: *client}, nil
}

func (d *DB) Exists(groupID, artifactID string) (bool, error) {
	index, err := d.client.SelectIndexByArtifactIDAndGroupID(artifactID, groupID)
	if err != nil {
		return false, err
	}
	return index.ArtifactID != "", nil
}

func (d *DB) SearchBySHA1(sha1 string) (jar.Properties, error) {
	index, err := d.client.SelectIndexBySha1(sha1)
	if err != nil {
		return jar.Properties{}, xerrors.Errorf("select error: %w", err)
	} else if index.ArtifactID == "" {
		return jar.Properties{}, xerrors.Errorf("digest %s: %w", sha1, jar.ArtifactNotFoundErr)
	}
	return jar.Properties{
		GroupID:    index.GroupID,
		ArtifactID: index.ArtifactID,
		Version:    index.Version,
	}, nil
}

func (d *DB) SearchByArtifactID(artifactID string) (string, error) {
	indexes, err := d.client.SelectIndexesByArtifactIDAndFileType(artifactID, types.JarType)
	if err != nil {
		return "", xerrors.Errorf("select error: %w", err)
	} else if len(indexes) == 0 {
		return "", xerrors.Errorf("artifactID %s: %w", artifactID, jar.ArtifactNotFoundErr)
	}
	sort.Slice(indexes, func(i, j int) bool {
		return indexes[i].GroupID < indexes[j].GroupID
	})

	// Some artifacts might have the same artifactId.
	// e.g. "javax.servlet:jstl" and "jstl:jstl"
	groupIDs := map[string]int{}
	for _, index := range indexes {
		if i, ok := groupIDs[index.GroupID]; ok {
			groupIDs[index.GroupID] = i + 1
			continue
		}
		groupIDs[index.GroupID] = 1
	}
	maxCount := 0
	var groupID string
	for k, v := range groupIDs {
		if v > maxCount {
			maxCount = v
			groupID = k
		}
	}

	return groupID, nil
}
